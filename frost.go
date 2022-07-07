package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"

	"github.com/renproject/secp256k1"
)

const (
	TypeCommitmentRequest = byte(0x00)
	TypeCommitment        = byte(0x01)
	TypeContributions     = byte(0x02)
	TypeZ                 = byte(0x03)
)

type Message struct {
	Type byte
	Data []byte
}

type Commitment struct {
	D, E secp256k1.Point
}

func (c *Commitment) Bytes(dst []byte) {
	c.D.PutBytes(dst)
	dst = dst[secp256k1.PointSizeMarshalled:]
	c.E.PutBytes(dst)
}

type Nonce struct {
	D, E secp256k1.Fn
}

type IndexedCommitment struct {
	Index uint16
	Commitment
}

type IndexedZ struct {
	Index uint16
	Z     secp256k1.Fn
}

type SAState struct {
	IndexedCommitments  []IndexedCommitment
	CommitmentsReceived int
	IndexedZs           []IndexedZ
	ZsReceived          int

	HashBuffer []byte
	RsBuffer   []secp256k1.Point
}

func NewSAState(t int) SAState {
	indexedCommitments := make([]IndexedCommitment, t)
	indexedZs := make([]IndexedZ, t)
	hashBuffer := make([]byte, 32+t*(2*secp256k1.PointSizeMarshalled+2))
	rsBuffer := make([]secp256k1.Point, t)

	return SAState{
		IndexedCommitments: indexedCommitments,
		IndexedZs:          indexedZs,
		ZsReceived:         0,

		HashBuffer: hashBuffer,
		RsBuffer:   rsBuffer,
	}
}

func (s *SAState) Reset(msgHash [32]byte) {
	// NOTE: This will apparently produce optimised code. See
	// https://github.com/golang/go/commit/f03c9202c43e0abb130669852082117ca50aa9b1
	for i := range s.HashBuffer {
		s.HashBuffer[i] = 0
	}
	copy(s.HashBuffer, msgHash[:])

	// @Performance: Does this produce optimized code as in the case of the
	// byte slice above? Probably not. If not, can we do anything about that?
	for i := range s.IndexedCommitments {
		s.IndexedCommitments[i] = IndexedCommitment{}
	}

	s.CommitmentsReceived = 0
	s.ZsReceived = 0
}

type State struct {
	Nonce
	Done bool
}

type InstanceParameters struct {
	Indices      []uint16
	PubKeyShares []secp256k1.Point
}

func NewInstanceParameters(inds []uint16, allPubKeyShares []secp256k1.Point) InstanceParameters {
	indices := make([]uint16, len(inds))
	copy(indices, inds)

	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	if int(indices[len(indices)-1]) > len(allPubKeyShares) {
		panic(fmt.Sprintf("indices must be less than or equal to %v, but found index %v", len(allPubKeyShares), indices[len(indices)-1]))
	}

	// Safetey check: later functions assume that the list of indices contains
	// no duplicates.
	curr := indices[0]
	for _, i := range indices[1:] {
		if curr == i {
			panic(fmt.Sprintf("duplicate index %v", curr))
		} else {
			curr = i
		}
	}

	// @Performance: It could get expensive to make a copy of the pubkeys we
	// are interested in, however taking references could cause very confusing
	// and potentially bad bugs if the referred to slice changes during a
	// signature, which it potentially could when the player list is updated.
	pubKeyShares := make([]secp256k1.Point, 0, len(indices))
	for _, i := range indices {
		pubKeyShares = append(pubKeyShares, allPubKeyShares[i-1])
	}

	return InstanceParameters{Indices: indices, PubKeyShares: pubKeyShares}
}

func SAHandleCommitment(state *SAState, indices []uint16, from uint16, commitmentBytes []byte) error {
	if len(commitmentBytes) != 2*secp256k1.PointSizeMarshalled {
		return fmt.Errorf("serialised commitment length invalid: expected %v, got %v", 2*secp256k1.PointSizeMarshalled, len(commitmentBytes))
	}

	var commitment IndexedCommitment

	commitment.Index = from

	err := commitment.D.SetBytes(commitmentBytes)
	if err != nil {
		return err
	}

	err = commitment.E.SetBytes(commitmentBytes[secp256k1.PointSizeMarshalled:])
	if err != nil {
		return err
	}

	offset := offsetOfPlayer(from, indices)
	baseIndex := 32 + offset*(2+2*secp256k1.PointSizeMarshalled)

	// If the commitment is unset, then the player index in the buffer will be
	// zero.
	alreadyHaveCommitment := state.HashBuffer[baseIndex] != 0x0 || state.HashBuffer[baseIndex+1] != 0x0
	if alreadyHaveCommitment {
		return fmt.Errorf("already received commitment from player %v", from)
	}

	binary.LittleEndian.PutUint16(state.HashBuffer[baseIndex:], from)

	copy(state.HashBuffer[baseIndex+2:], commitmentBytes[:secp256k1.PointSizeMarshalled])
	copy(state.HashBuffer[baseIndex+2+secp256k1.PointSizeMarshalled:], commitmentBytes[secp256k1.PointSizeMarshalled:])

	state.IndexedCommitments[offset] = commitment
	state.CommitmentsReceived++

	return nil
}

func SAHandleZ(state *SAState, indices []uint16, from uint16, zBytes []byte) error {
	if len(zBytes) != 32 {
		return fmt.Errorf("invalid z encoding length: expected 32, got %v", len(zBytes))
	}

	var z secp256k1.Fn
	z.SetB32(zBytes)

	offset := offsetOfPlayer(from, indices)

	alreadyHaveZ := state.IndexedZs[offset].Index != 0
	if alreadyHaveZ {
		return fmt.Errorf("already have z from player %v", from)
	}

	state.IndexedZs[offset] = IndexedZ{Index: from, Z: z}
	state.ZsReceived++

	return nil
}

func offsetOfPlayer(player uint16, players []uint16) int {
	for i, index := range players {
		if index == player {
			return i
		}
	}

	panic(fmt.Sprintf("unable to find player %v in the list of players", player))
}

func SAComputeSignature(state *SAState, y *secp256k1.Point, yis []secp256k1.Point, indices []uint16, requireEvenY bool) (secp256k1.Point, secp256k1.Fn, error) {
	r := computeAllRs(state.RsBuffer, state.IndexedCommitments, state.HashBuffer)
	rHasEvenY := hasEvenY(&r)

	msgHash := state.HashBuffer[:32]
	c := computeC(&r, y, msgHash)

	for i, yi := range yis {
		if requireEvenY && !rHasEvenY {
			negatePoint(&state.RsBuffer[i])
		}

		if !validateZ(state.IndexedZs[i].Index, indices, &state.IndexedZs[i].Z, &c, &state.RsBuffer[i], &yi) {
			return secp256k1.Point{}, secp256k1.Fn{}, fmt.Errorf("invalid z received from player %v", state.IndexedZs[i].Index)
		}
	}

	z := state.IndexedZs[0].Z
	for _, zi := range state.IndexedZs[1:] {
		z.Add(&z, &zi.Z)
	}

	return r, z, nil
}

func SAHandleMessage(msg Message, from uint16, state *SAState, y *secp256k1.Point, params InstanceParameters) (bool, secp256k1.Point, secp256k1.Fn, bool, Message, error) {
	t := len(params.Indices)

	switch msg.Type {
	case TypeCommitment:
		err := SAHandleCommitment(state, params.Indices, from, msg.Data)
		if err != nil {
			return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, fmt.Errorf("error handling commitment: %v", err)
		}

		if state.CommitmentsReceived == t {
			contributionBytes := make([]byte, len(state.HashBuffer))
			copy(contributionBytes, state.HashBuffer)

			return false, secp256k1.Point{}, secp256k1.Fn{}, true, Message{Type: TypeContributions, Data: contributionBytes}, nil
		} else {
			return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, nil
		}

	case TypeZ:
		err := SAHandleZ(state, params.Indices, from, msg.Data)
		if err != nil {
			return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, fmt.Errorf("error handling z: %v", err)
		}

		if state.ZsReceived == t {
			r, s, err := SAComputeSignature(state, y, params.PubKeyShares, params.Indices, true)
			if err != nil {
				return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, fmt.Errorf("error computing signature: %v", err)
			}

			return true, r, s, false, Message{}, nil
		} else {
			return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, nil
		}

	default:
		return false, secp256k1.Point{}, secp256k1.Fn{}, false, Message{}, fmt.Errorf("unexpected message type for aggregator %v", msg.Type)
	}
}

func RandomNonceCommitmentPair() (Nonce, Commitment) {
	d, e := secp256k1.RandomFn(), secp256k1.RandomFn()

	var gd, ge secp256k1.Point
	gd.BaseExp(&d)
	ge.BaseExp(&e)

	return Nonce{D: d, E: e}, Commitment{D: gd, E: ge}
}

// Assumed message format:
// - [0:32] message hash
// - [32:]  list of commitments, no length prefix
// We assume that the commitments are ordered by their index in ascending
// order. It is the responsibility of the SA to have the list sorted thusly.
func HandleSAProposal(nonce *Nonce, si *secp256k1.Fn, y *secp256k1.Point, index uint16, n, t int, msgBytes []byte, requireEvenY bool) (secp256k1.Fn, error) {
	byteScanner := msgBytes
	msgHash := byteScanner[:32]
	byteScanner = byteScanner[32:]

	commitmentSize := 2 + 2*secp256k1.PointSizeMarshalled
	if len(byteScanner)%commitmentSize != 0 {
		return secp256k1.Fn{}, fmt.Errorf("invalid commitment list size %v should be divisible by %v", len(byteScanner), commitmentSize)
	}

	subsetSize := len(byteScanner) / commitmentSize
	if subsetSize < t || n < subsetSize {
		return secp256k1.Fn{}, fmt.Errorf("invalid number of commitments %v: expected a number between t = %v and n = %v", subsetSize, t, n)
	}

	// @Safety: The following iterates through the message bytes at for each
	// commitment checks that it is valid and then deserialises into our type.
	// This requies us to allocate our memory up front (we don't want
	// reallocations from resizing a small slice).  Therefore a malicious
	// player could cause us to do this (potentially large) allocation work
	// unnecessarily.  We might want to do a first pass over the message bytes
	// to make sure that the curve points (and indices too probably) are valid,
	// and then we can allocate knowing that it will not be wasted work. This
	// will probably involve a new method for the `secp256k1.Point` type that
	// can do this check, as the current approach of simply deserialising and
	// then checking the error does extra unnecessary work.
	commitments := make([]IndexedCommitment, subsetSize)

	// @Performance: We might want to take some preallocated memory as an
	// argument to avoid doing an allocation here evey time. The same applies
	// to the above allocation.
	indices := make([]uint16, 0, subsetSize)

	var prevInd, currInd uint16
	for i := 0; i < subsetSize; i++ {
		ind := binary.LittleEndian.Uint16(byteScanner)
		byteScanner = byteScanner[2:]

		if ind < 1 || n < int(ind) {
			return secp256k1.Fn{}, fmt.Errorf("index %v out of range [1, %v]", ind, n)
		}

		if i == 0 {
			prevInd = ind
			currInd = ind
		} else {
			prevInd = currInd
			currInd = ind
			if currInd <= prevInd {
				return secp256k1.Fn{}, fmt.Errorf("index list not increasing")
			}
		}

		indices = append(indices, ind)

		var commitment IndexedCommitment
		if err := commitment.D.SetBytes(byteScanner); err != nil {
			return secp256k1.Fn{}, fmt.Errorf("invalid curve point: %v", err)
		}
		byteScanner = byteScanner[secp256k1.PointSizeMarshalled:]
		if err := commitment.E.SetBytes(byteScanner); err != nil {
			return secp256k1.Fn{}, fmt.Errorf("invalid curve point: %v", err)
		}
		byteScanner = byteScanner[secp256k1.PointSizeMarshalled:]
		commitment.Index = ind

		commitments[i] = commitment
	}

	r, rho := computeRAndRho(commitments, msgBytes, index)
	if requireEvenY && !hasEvenY(&r) {
		nonce.D.Negate(&nonce.D)
		nonce.E.Negate(&nonce.E)
	}
	c := computeC(&r, y, msgHash)
	z := computeZ(index, indices, &nonce.D, &nonce.E, &rho, si, &c)

	return z, nil
}

func Handle(msg Message, state *State, index uint16, privKeyShare *secp256k1.Fn, y *secp256k1.Point, n, t int, isFromAggregator bool) (Message, error) {
	// @Design: This obviously looks like a weird approach to not accepting
	// messages that aren't from the aggregator. The reasoning is: we do not
	// want to assume what "network" form the identities of the players assume,
	// but it is necessary to know this to be able to check if the message is
	// coming from the current aggregator, which implies that this check needs
	// to exist at a higher level. But on the other hand, this check is
	// potentially important, so we want to ensure that it happens. This
	// current approach at a minimum gives a compile time reminder to a caller
	// of this function that the check needs to occur.
	if !isFromAggregator {
		return Message{}, errors.New("message does not come from aggregator")
	}

	switch msg.Type {
	case TypeCommitmentRequest:
		if state.Nonce != (Nonce{}) {
			// TODO(ross): Need to think about how to handle switching to a new
			// aggregator if the first one doesn't complete within the timeout.
			// Returning an error in this case implies that it is the
			// responsibility of the caller of this function to reset the
			// player state when a new aggregator is selected.
			return Message{}, errors.New("already handled a commitment request")
		}

		nonce, commitment := RandomNonceCommitmentPair()

		state.Nonce = nonce

		var commitmentBytes [66]byte
		commitment.Bytes(commitmentBytes[:])

		return Message{Type: TypeCommitment, Data: commitmentBytes[:]}, nil

	case TypeContributions:
		if state.Done {
			return Message{}, errors.New("already handled contributions")
		}

		z, err := HandleSAProposal(&state.Nonce, privKeyShare, y, index, n, t, msg.Data, true)
		if err != nil {
			return Message{}, err
		}

		state.Done = true

		var zBytes [32]byte
		z.PutB32(zBytes[:])

		return Message{Type: TypeZ, Data: zBytes[:]}, nil

	default:
		return Message{}, fmt.Errorf("unexpected message type for player %v", msg.Type)
	}
}

func computeRAndRho(commitments []IndexedCommitment, msgAndCommitmentBytes []byte, index uint16) (secp256k1.Point, secp256k1.Fn) {
	var rho, rhoi secp256k1.Fn
	var r, temp secp256k1.Point

	hasher := sha256.New()
	for i, commitment := range commitments {
		computeRLoopStep(commitment, hasher, msgAndCommitmentBytes, &rhoi, &r, &temp, i == 0)

		if commitment.Index == index {
			rho = rhoi
		}
	}

	return r, rho
}

func computeAllRs(dst []secp256k1.Point, commitments []IndexedCommitment, msgAndCommitmentBytes []byte) secp256k1.Point {
	var rhoi secp256k1.Fn
	var r, temp secp256k1.Point

	hasher := sha256.New()
	for i, commitment := range commitments {
		computeRLoopStep(commitment, hasher, msgAndCommitmentBytes, &rhoi, &r, &temp, i == 0)

		dst[i] = temp
	}

	return r
}

func computeRLoopStep(commitment IndexedCommitment, hasher hash.Hash, msgAndCommitmentBytes []byte, rhoi *secp256k1.Fn, r, temp *secp256k1.Point, first bool) {
	var indexBuffer [2]byte
	binary.LittleEndian.PutUint16(indexBuffer[:], commitment.Index)

	// @Performance: We are making a trade off here. Writing to the hasher
	// twice (when the first write is not a multiple of the chunk, which it
	// isn't) means that it will need to copy the remainder of the first
	// write instead of being able to consider it as part of the first
	// chunk from the beginning.  However, if we wanted to only do one
	// write we would have to have the extra two bytes of space at the
	// front of the msgAndCommitmentBytes slice to write it in all at once,
	// but this would require copying the whole message byte slice at some
	// point and probably a reallocation, which probably would be more
	// expensive overall since the message byte slice could be fairly big
	// (We could of course get around needing to copy/allocate in theory
	// but it would probably make the deserialisation logic
	// annoying/complicated).
	hasher.Write(indexBuffer[:])
	hasher.Write(msgAndCommitmentBytes)
	hash := hasher.Sum(nil)
	hasher.Reset()

	rhoi.SetB32(hash[:])

	temp.Scale(&commitment.E, rhoi)
	temp.Add(temp, &commitment.D)
	if first {
		*r = *temp
	} else {
		r.Add(r, temp)
	}
}

func computeC(r, y *secp256k1.Point, message []byte) secp256k1.Fn {
	// @Performance: Ideally we have a method on the `Point` type that allows
	// us to directly serialise only the x coordinate.
	var rBytes, yBytes [33]byte

	r.PutBytes(rBytes[:])
	y.PutBytes(yBytes[:])

	hash := taggedHash(rBytes[1:], yBytes[1:], message)

	c := secp256k1.Fn{}
	c.SetB32(hash[:])

	return c
}

func computeZ(i uint16, indices []uint16, di, ei, rhoi, si, c *secp256k1.Fn) secp256k1.Fn {
	var zi secp256k1.Fn

	lambdai := lagrangeCoefficient(i, indices)

	zi.Mul(ei, rhoi)
	lambdai.Mul(&lambdai, si)
	lambdai.Mul(&lambdai, c)
	zi.Add(&zi, &lambdai)
	zi.Add(&zi, di)

	return zi
}

func validateZ(i uint16, indices []uint16, zi, c *secp256k1.Fn, ri, yi *secp256k1.Point) bool {
	lambdai := lagrangeCoefficient(i, indices)

	var lhs, rhs secp256k1.Point

	lhs.BaseExp(zi)

	var prod secp256k1.Fn
	prod.Mul(c, &lambdai)
	rhs.Scale(yi, &prod)
	rhs.Add(&rhs, ri)

	return lhs.Eq(&rhs)
}

func lagrangeCoefficient(i uint16, indices []uint16) secp256k1.Fn {
	iFn := secp256k1.NewFnFromU16(i)
	numerator := secp256k1.NewFnFromU16(1)
	denominator := secp256k1.NewFnFromU16(1)

	var temp secp256k1.Fn
	for _, j := range indices {
		if j == i {
			continue
		}

		jFn := secp256k1.NewFnFromU16(uint16(j))

		numerator.Mul(&numerator, &jFn)

		temp.Negate(&iFn)
		temp.Add(&temp, &jFn)
		denominator.Mul(&denominator, &temp)
	}

	denominator.Inverse(&denominator)
	numerator.Mul(&numerator, &denominator)

	return numerator
}

// TODO(ross): This should be probably be defined in the secp256k1 package (and
// there might be a more efficient implementation possible there.
func negatePoint(p *secp256k1.Point) {
	x, y, err := p.XY()
	if err != nil {
		panic(err)
	}

	y.Negate(&y)
	p.SetXY(&x, &y)
}

// TODO(ross): This should be probably be defined in the secp256k1 package (and
// there might be a more efficient implementation possible there.
func hasEvenY(p *secp256k1.Point) bool {
	_, y, err := p.XY()
	if err != nil {
		panic(err)
	}

	return y.IsEven()
}
