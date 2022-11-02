package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/renproject/frost/xoroshiro"
	"github.com/renproject/secp256k1"
)

const (
	MessageTypePlayer    = byte(0x00)
	MessageTypeSA        = byte(0x01)
	MessageTypeSignature = byte(0x02)
)

type RoastPlayerState struct {
	nonces []Nonce
}

func NewRoastPlayerState() RoastPlayerState {
	return RoastPlayerState{
		nonces: make([]Nonce, 0, 1),
	}
}

func (state *RoastPlayerState) Reset() {
	state.nonces = state.nonces[:0]
}

type RoastSAState struct {
	responsiveSet      map[uint16]struct{}
	maliciousSet       map[uint16]error
	commitments        map[uint16]Commitment
	sid                int
	sidForPlayer       map[uint16]int
	subsetForSID       [][]uint16
	presignatureForSID []secp256k1.Point
	zsForSID           [][]secp256k1.Fn

	commitmentBytes map[uint16][]byte
	rsForSID        []map[uint16]secp256k1.Point
	cForSID         []secp256k1.Fn
}

func NewRoastSAState(n, t int) RoastSAState {
	// We allocate memory in an optimistic way: we allocate the minimum amount
	// that would be required if we pick an honest subset first time. The extra
	// memory required in the case of dealing with malicious/unresponsive nodes
	// should only end up being allocated infrequently, and so shouldn't have a
	// significant impact on performance.
	return RoastSAState{
		responsiveSet:      make(map[uint16]struct{}, t),
		maliciousSet:       map[uint16]error{},
		commitments:        make(map[uint16]Commitment, n),
		sid:                0,
		sidForPlayer:       make(map[uint16]int, n),
		subsetForSID:       make([][]uint16, 0, 1),
		presignatureForSID: make([]secp256k1.Point, 0, 1),
		zsForSID:           make([][]secp256k1.Fn, 0, 1),

		commitmentBytes: make(map[uint16][]byte, n),
		rsForSID:        make([]map[uint16]secp256k1.Point, 0, 1),
		cForSID:         make([]secp256k1.Fn, 0, 1),
	}
}

func (state *RoastSAState) Reset() {
	for index := range state.responsiveSet {
		delete(state.responsiveSet, index)
	}
	for index := range state.maliciousSet {
		delete(state.maliciousSet, index)
	}
	for index := range state.commitments {
		delete(state.commitments, index)
	}
	state.sid = 0
	for index := range state.sidForPlayer {
		delete(state.sidForPlayer, index)
	}
	state.subsetForSID = state.subsetForSID[:0]
	state.presignatureForSID = state.presignatureForSID[:0]
	state.zsForSID = state.zsForSID[:0]

	for index := range state.commitmentBytes {
		delete(state.commitmentBytes, index)
	}
	state.rsForSID = state.rsForSID[:0]
	state.cForSID = state.cForSID[:0]
}

type RoastState struct {
	playerState RoastPlayerState
	saState     RoastSAState

	saCursor     int
	saSchedule   []uint16
	maliciousSAs map[uint16]error
}

func NewRoastState(n, t int, indices []uint16, sighash [32]byte) RoastState {
	return RoastState{
		playerState: NewRoastPlayerState(),
		saState:     NewRoastSAState(n, t),

		saCursor:     0,
		saSchedule:   shuffledFromSeed(indices, sighash[:]),
		maliciousSAs: map[uint16]error{},
	}
}

func (state *RoastState) Reset(indices []uint16, sighash []byte) {
	state.playerState.Reset()
	state.saState.Reset()
	state.saCursor = 0
	state.saSchedule = shuffledFromSeed(indices, sighash)
	for index := range state.maliciousSAs {
		delete(state.maliciousSAs, index)
	}
}

func shuffledFromSeed(list []uint16, seed []byte) []uint16 {
	shuffled := make([]uint16, len(list))
	copy(shuffled, list)

	rng := xoroshiro.Rng{}
	rng.Seed(seed)

	for i := len(shuffled) - 1; i > 0; i-- {
		swapIndex := rng.Uint64() % (uint64(i) + 1)
		shuffled[i], shuffled[swapIndex] = shuffled[swapIndex], shuffled[i]
	}

	return shuffled
}

type Parameters struct {
	N, T   int
	BIP340 bool

	OwnIndex     uint16
	PrivKeyShare secp256k1.Fn
	PubKeyShares map[uint16]secp256k1.Point
	PubKey       secp256k1.Point
}

type SignatureOutput struct {
	Done bool
	R    secp256k1.Point
	S    secp256k1.Fn
}

func SignatureOutputNotDone() SignatureOutput {
	return SignatureOutput{Done: false}
}

type DestinationType uint

const (
	DestinationTypeNone   = 0
	DestinationTypeOne    = 1
	DestinationTypeSubset = 2
	DestinationTypeAll    = 3
)

type MessageOutput struct {
	Destination DestinationType
	To          uint16
	Subset      []uint16
	Message
}

func MessageOutputNone() MessageOutput {
	return MessageOutput{Destination: DestinationTypeNone}
}

func RoastStart(state *RoastState, params Parameters) MessageOutput {
	return startNewSA(state, params)
}

func RoastHandle(state *RoastState, params Parameters, sighash [32]byte, msg Message, from uint16) (SignatureOutput, MessageOutput) {
	// TODO(ross): What about `from` not being in the index set?

	switch msg.Type {
	case MessageTypePlayer:

		sig, msg := roastSAHandle(&state.saState, params, sighash, from, msg.Data)

		return sig, msg

	case MessageTypeSA:

		msg := roastPlayerHandle(state, params, sighash[:], from, msg.Data)

		return SignatureOutputNotDone(), msg

	case MessageTypeSignature:

		sig := roastHandleSignature(state, params, sighash, from, msg.Data)

		return sig, MessageOutputNone()

	default:
		// TODO(ross): Add to malicious players list.
		// fmt.Errorf("unexpected message type %v", msg.Type)
		return SignatureOutputNotDone(), MessageOutputNone()
	}
}

func RoastAdvanceSA(state *RoastState, params Parameters) MessageOutput {
	state.saCursor++

	return startNewSA(state, params)
}

func startNewSA(state *RoastState, params Parameters) MessageOutput {
	currentSA := state.saSchedule[state.saCursor]

	if currentSA == params.OwnIndex {
		return MessageOutputNone()
	}

	newNonce, newCommitment := NewNonceAndCommitment()

	state.playerState.nonces = append(state.playerState.nonces, newNonce)

	outgoingMessageBytes := make([]byte, CommitmentSizeMarshalled)
	newCommitment.Bytes(outgoingMessageBytes)

	msg := MessageOutput{
		Destination: DestinationTypeOne,
		To:          currentSA,
		Message: Message{
			Type: MessageTypePlayer,
			Data: outgoingMessageBytes,
		},
	}

	return msg
}

func roastSAHandle(state *RoastSAState, params Parameters, sigHash [32]byte, from uint16, msgBytes []byte) (SignatureOutput, MessageOutput) {
	if len(msgBytes) < CommitmentSizeMarshalled {
		markMalicious(state, params.N, params.T, from, fmt.Errorf("invalid message length %v, should be at least %v", len(msgBytes), CommitmentSizeMarshalled))
		return SignatureOutputNotDone(), MessageOutputNone()
	}

	commitmentBytes := msgBytes[:CommitmentSizeMarshalled]
	zBytes := msgBytes[CommitmentSizeMarshalled:]

	if len(zBytes) != 0 && len(zBytes) != ZSizeMarshalled {
		markMalicious(state, params.N, params.T, from, fmt.Errorf("invalid z marshalled length %v, should be 0 or %v", len(zBytes), ZSizeMarshalled))
		return SignatureOutputNotDone(), MessageOutputNone()
	}

	var commitment Commitment
	var z secp256k1.Fn

	err := commitment.SetBytes(commitmentBytes)
	if err != nil {
		markMalicious(state, params.N, params.T, from, err)
		return SignatureOutputNotDone(), MessageOutputNone()
	}

	if len(zBytes) != 0 {
		z.SetB32(zBytes)
	}

	if _, ok := state.maliciousSet[from]; ok {
		return SignatureOutputNotDone(), MessageOutputNone()
	}

	if _, ok := state.responsiveSet[from]; ok {
		markMalicious(state, params.N, params.T, from, errors.New("out of turn ROAST message"))
		return SignatureOutputNotDone(), MessageOutputNone()
	}

	if sid, ok := state.sidForPlayer[from]; ok {
		subset := state.subsetForSID[sid]
		presignature := state.presignatureForSID[sid]
		// commitment := state.commitments[from]

		c := state.cForSID[sid]
		ri := state.rsForSID[sid][from]
		yi := params.PubKeyShares[from]

		if !validateZ(from, subset, &z, &c, &ri, &yi) {
			markMalicious(state, params.N, params.T, from, errors.New("invalid z"))
			return SignatureOutputNotDone(), MessageOutputNone()
		}

		state.zsForSID[sid] = append(state.zsForSID[sid], z)

		if len(state.zsForSID[sid]) == params.T {
			z := state.zsForSID[sid][0]
			for _, zi := range state.zsForSID[sid][1:] {
				z.Add(&z, &zi)
			}

			sig := SignatureOutput{
				Done: true,
				R:    presignature,
				S:    z,
			}

			sigBytes := make([]byte, secp256k1.PointSizeMarshalled+secp256k1.FnSizeMarshalled)
			presignature.PutBytes(sigBytes[:secp256k1.PointSizeMarshalled])
			z.PutB32(sigBytes[secp256k1.PointSizeMarshalled:])

			msg := MessageOutput{
				Destination: DestinationTypeAll,
				Message: Message{
					Type: MessageTypeSignature,
					Data: sigBytes,
				},
			}

			return sig, msg
		}
	}

	state.commitments[from] = commitment
	state.commitmentBytes[from] = commitmentBytes
	state.responsiveSet[from] = struct{}{}

	if len(state.responsiveSet) == params.T {
		sid := state.sid
		state.sid++

		state.subsetForSID = append(state.subsetForSID, make([]uint16, 0, params.T))
		for index := range state.responsiveSet {
			state.sidForPlayer[index] = sid
			state.subsetForSID[sid] = append(state.subsetForSID[sid], index)

			delete(state.responsiveSet, index)
		}

		sort.Slice(state.subsetForSID[sid], func(i, j int) bool { return state.subsetForSID[sid][i] < state.subsetForSID[sid][j] })

		stride := 2 + CommitmentSizeMarshalled
		data := make([]byte, 32+stride*params.T)

		copy(data[:32], sigHash[:])

		rsBytes := data[32:]
		for i, index := range state.subsetForSID[sid] {
			binary.LittleEndian.PutUint16(rsBytes[i*stride:], index)
			copy(rsBytes[i*stride+2:], state.commitmentBytes[index])
		}

		state.rsForSID = append(state.rsForSID, make(map[uint16]secp256k1.Point, params.T))
		r := computeRs(state.rsForSID[sid], state.commitments, sigHash[:], rsBytes)
		state.presignatureForSID = append(state.presignatureForSID, r)
		state.cForSID = append(state.cForSID, computeC(&r, &params.PubKey, sigHash[:], params.BIP340))
		state.zsForSID = append(state.zsForSID, make([]secp256k1.Fn, 0, params.T))

		msg := MessageOutput{
			Destination: DestinationTypeSubset,
			// TODO(ross): This is technically dangerous since the slice could
			// get modified after returning, however this is unlikely and it
			// would be annoying to have to copy the optentially large slice
			// just to avoid this possibility. What to do?
			Subset: state.subsetForSID[sid],
			Message: Message{
				Type: MessageTypeSA,
				Data: data,
			},
		}

		return SignatureOutputNotDone(), msg
	}

	return SignatureOutputNotDone(), MessageOutputNone()
}

func markMalicious(state *RoastSAState, n, t int, from uint16, err error) {
	state.maliciousSet[from] = err

	if len(state.maliciousSet) > n-t {
		// TODO(ross): This is a violation of the system assumption.
	}
}

func computeRs(rsDst map[uint16]secp256k1.Point, commitments map[uint16]Commitment, msgHash []byte, rsBytes []byte) secp256k1.Point {
	var indexBuffer [2]byte
	var rhoi secp256k1.Fn
	var ri secp256k1.Point
	hasher := sha256.New()

	r := secp256k1.NewPointInfinity()

	for index, commitment := range commitments {
		binary.LittleEndian.PutUint16(indexBuffer[:], index)

		hasher.Write(indexBuffer[:])
		hasher.Write(msgHash)
		hasher.Write(rsBytes)
		hash := hasher.Sum(nil)
		hasher.Reset()

		rhoi.SetB32(hash[:])

		ri.Scale(&commitment.E, &rhoi)
		ri.Add(&ri, &commitment.D)

		rsDst[index] = ri
		r.Add(&r, &ri)
	}

	return r
}

// Assumptions:
// - `from` is a valid index and hence exists in the `saSchedule`
func roastPlayerHandle(state *RoastState, params Parameters, sighash []byte, from uint16, msgBytes []byte) MessageOutput {
	if _, ok := state.maliciousSAs[from]; ok {
		// TODO(ross): Do we return an error here or just do some logging?
		return MessageOutputNone()
	}

	saPosition := -1
	for i := range state.saSchedule {
		if from == state.saSchedule[i] {
			saPosition = i
			break
		}
	}

	if saPosition == -1 {
		panic(fmt.Sprintf("index %v does not exist in the sa schedule", from))
	}

	if saPosition > state.saCursor {
		state.maliciousSAs[from] = fmt.Errorf("unsolicited message from aggregator %v: current position is %v but their position is %v", from, state.saCursor, saPosition)
		return MessageOutputNone()
	}

	currentNonce := state.playerState.nonces[saPosition]

	z, err := HandleSAProposal(currentNonce, &params.PrivKeyShare, &params.PubKey, sighash, params.OwnIndex, params.N, params.T, msgBytes, params.BIP340)
	if err != nil {
		state.maliciousSAs[from] = err
		return MessageOutputNone()
	}

	newNonce, newCommitment := NewNonceAndCommitment()
	state.playerState.nonces[saPosition] = newNonce

	outgoingMessageBytes := make([]byte, CommitmentSizeMarshalled+ZSizeMarshalled)
	newCommitment.Bytes(outgoingMessageBytes[:CommitmentSizeMarshalled])
	z.PutB32(outgoingMessageBytes[CommitmentSizeMarshalled:])

	messageOutput := MessageOutput{
		Destination: DestinationTypeOne,
		To:          from,
		Message: Message{
			Type: MessageTypePlayer,
			Data: outgoingMessageBytes,
		},
	}

	return messageOutput
}

func SigIsValid(r *secp256k1.Point, s *secp256k1.Fn, msgHash *[32]byte, pubKey *secp256k1.Point, bip340 bool) bool {
	rBytes := make([]byte, 33)
	pubKeyBytes := make([]byte, 33)
	r.PutBytes(rBytes)
	pubKey.PutBytes(pubKeyBytes)

	var e secp256k1.Fn
	var eBytes []byte
	if bip340 {
		eBytes = TaggedHash(rBytes[1:], pubKeyBytes[1:], msgHash[:])
	} else {
		eBytes = CHash(rBytes, pubKeyBytes, msgHash[:])
	}
	e.SetB32(eBytes)
	e.Negate(&e)

	var sG, eP, computedR secp256k1.Point
	sG.BaseExp(s)
	eP.Scale(pubKey, &e)
	computedR.Add(&sG, &eP)

	return computedR.Eq(r)
}

func roastHandleSignature(state *RoastState, params Parameters, sighash [32]byte, from uint16, msgBytes []byte) SignatureOutput {
	expectedLen := secp256k1.PointSizeMarshalled + secp256k1.FnSizeMarshalled
	if len(msgBytes) != expectedLen {
		state.maliciousSAs[from] = fmt.Errorf("invalid signature message length: expected %v, got %v", expectedLen, len(msgBytes))
		return SignatureOutputNotDone()
	}

	var r secp256k1.Point
	var s secp256k1.Fn

	err := r.SetBytes(msgBytes[:secp256k1.PointSizeMarshalled])
	if err != nil {
		state.maliciousSAs[from] = err
		return SignatureOutputNotDone()
	}

	s.SetB32(msgBytes[secp256k1.PointSizeMarshalled:])

	if !SigIsValid(&r, &s, &sighash, &params.PubKey, params.BIP340) {
		state.maliciousSAs[from] = errors.New("invalid signature")
		return SignatureOutputNotDone()
	}

	sig := SignatureOutput{
		Done: true,
		R:    r,
		S:    s,
	}

	return sig
}
