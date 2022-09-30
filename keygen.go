package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/renproject/secp256k1"
)

const (
	DKGTypeContribution = byte(0x00)
	DKGTypeShare        = byte(0x01)
)

const ProofLenMarshalled int = secp256k1.PointSizeMarshalled + secp256k1.FnSizeMarshalled

type DKGMessage struct {
	Type byte
	Data []byte
}

type DKGMessageTo struct {
	DKGMessage
	To uint16
}

type Proof struct {
	R  secp256k1.Point
	Mu secp256k1.Fn
}

func (p *Proof) PutBytes(dst []byte) {
	p.R.PutBytes(dst[0:secp256k1.PointSizeMarshalled])
	p.Mu.PutB32(dst[secp256k1.PointSizeMarshalled : secp256k1.PointSizeMarshalled+secp256k1.FnSizeMarshalled])
}

func (p *Proof) SetBytes(bs []byte) error {
	expectedLen := ProofLenMarshalled
	actualLen := len(bs)
	if actualLen != expectedLen {
		return fmt.Errorf("expected length %v but got %v", expectedLen, actualLen)
	}

	rSlice := bs[:secp256k1.PointSizeMarshalled]
	muSlice := bs[secp256k1.PointSizeMarshalled:]

	err := p.R.SetBytes(rSlice)
	if err != nil {
		return err
	}

	p.Mu.SetB32(muSlice)

	return nil
}

type DKGState struct {
	Coefficients []secp256k1.Fn
	Commitments  [][]secp256k1.Point
	Shares       []secp256k1.Fn

	ContributionsReceived int
	SharesReceived        int
}

func NewEmptyDKGState(n, t int) DKGState {
	coefficients := make([]secp256k1.Fn, t)
	commitments := make([][]secp256k1.Point, n)
	shares := make([]secp256k1.Fn, n)

	return DKGState{
		Coefficients: coefficients,
		Commitments:  commitments,
		Shares:       shares,

		ContributionsReceived: 0,
		SharesReceived:        0,
	}
}

func DKGStart(state *DKGState, indices []uint16, t int, ownIndex uint16, context [32]byte) DKGMessage {
	for i := range state.Commitments {
		state.Commitments[i] = nil
	}
	for i := range state.Shares {
		state.Shares[i] = secp256k1.NewFnFromU16(0)
	}

	coeffs := make([]secp256k1.Fn, t)
	for i := range coeffs {
		coeffs[i] = secp256k1.RandomFn()
	}
	state.Coefficients = coeffs

	commitments := make([]secp256k1.Point, t)
	for i := range commitments {
		commitments[i].BaseExp(&coeffs[i])
	}

	sliceIndex := offsetOfPlayer(ownIndex, indices)
	if sliceIndex == -1 {
		panic("own index not in index set")
	}
	state.Commitments[sliceIndex] = commitments
	state.ContributionsReceived++

	var r secp256k1.Point
	k := secp256k1.RandomFn()
	r.BaseExp(&k)

	c := dkgComputeC(ownIndex, context, &commitments[0], &r)

	var mu secp256k1.Fn
	mu.Mul(&c, &coeffs[0])
	mu.Add(&mu, &k)

	proof := Proof{R: r, Mu: mu}

	data := make([]byte, ProofLenMarshalled+t*secp256k1.PointSizeMarshalled)
	proof.PutBytes(data[:ProofLenMarshalled])
	tail := data[ProofLenMarshalled:]
	for i := range commitments {
		commitments[i].PutBytes(tail[:secp256k1.PointSizeMarshalled])
		tail = tail[secp256k1.PointSizeMarshalled:]
	}

	return DKGMessage{Type: DKGTypeContribution, Data: data}
}

func DKGCheckContribution(from uint16, context [32]byte, secretCommitment *secp256k1.Point, proof Proof) bool {
	c := dkgComputeC(from, context, secretCommitment, &proof.R)
	c.Negate(&c)

	var muPoint secp256k1.Point
	muPoint.BaseExp(&proof.Mu)

	var check secp256k1.Point
	check.Scale(secretCommitment, &c)
	check.Add(&check, &muPoint)

	return proof.R.Eq(&check)
}

func dkgComputeC(from uint16, context [32]byte, secretCommitment, r *secp256k1.Point) secp256k1.Fn {
	var fromIndexBytes [2]byte
	binary.LittleEndian.PutUint16(fromIndexBytes[:], from)

	var secretCommitmentBytes [33]byte
	secretCommitment.PutBytes(secretCommitmentBytes[:])

	var rBytes [33]byte
	r.PutBytes(rBytes[:])

	h := sha256.New()
	h.Write(fromIndexBytes[:])
	h.Write(context[:])
	h.Write(secretCommitmentBytes[:])
	h.Write(rBytes[:])
	cBytes := h.Sum(nil)

	var c secp256k1.Fn
	c.SetB32(cBytes)

	return c
}

func DKGHandleContribution(state *DKGState, indices []uint16, context [32]byte, from uint16, commitments []secp256k1.Point, proof Proof) error {
	sliceIndex := offsetOfPlayer(from, indices)
	if sliceIndex < 0 {
		return fmt.Errorf("received contribution from player not in index list: from: %v", from)
	}

	if state.Commitments[sliceIndex] != nil {
		return errors.New("already handled commitment from player")
	}

	if !DKGCheckContribution(from, context, &commitments[0], proof) {
		return errors.New("invalid proof")
	}

	state.Commitments[sliceIndex] = commitments
	state.ContributionsReceived++

	return nil
}

func DKGHandleShare(state *DKGState, indices []uint16, ownIndex, from uint16, share secp256k1.Fn) error {
	sliceIndex := offsetOfPlayer(from, indices)
	if sliceIndex < 0 {
		return fmt.Errorf("received contribution from player not in index list: from: %v", from)
	}

	if state.Commitments[sliceIndex] == nil {
		return errors.New("share received before commitment")
	}

	if !state.Shares[sliceIndex].IsZero() {
		return errors.New("already received share from player")
	}

	if !verifyShare(ownIndex, share, state.Commitments[sliceIndex]) {
		return errors.New("invalid share")
	}

	state.Shares[sliceIndex] = share
	state.SharesReceived++

	return nil
}

func DKGHandleMessage(state *DKGState, ownIndex uint16, indices []uint16, t int, context [32]byte, message DKGMessage, from uint16) (bool, DKGOutput, []DKGMessageTo, error) {
	n := len(indices)

	switch message.Type {
	case DKGTypeContribution:
		expectedLen := ProofLenMarshalled + t*secp256k1.PointSizeMarshalled
		if len(message.Data) != expectedLen {
			return false, DKGOutput{}, nil, fmt.Errorf("invalid contribution message length: expected %v, got %v", expectedLen, len(message.Data))
		}

		proofBytes := message.Data[:ProofLenMarshalled]
		commitmentsBytes := message.Data[ProofLenMarshalled:]

		var proof Proof
		err := proof.SetBytes(proofBytes)
		if err != nil {
			return false, DKGOutput{}, nil, fmt.Errorf("invalid proof encoding: %v", err)
		}

		commitments := make([]secp256k1.Point, t)
		tail := commitmentsBytes
		for i := range commitments {
			err := commitments[i].SetBytes(tail)
			if err != nil {
				return false, DKGOutput{}, nil, fmt.Errorf("invalid curve point encoding: %v", err)
			}
			tail = tail[secp256k1.PointSizeMarshalled:]
		}

		err = DKGHandleContribution(state, indices, context, from, commitments, proof)
		if err != nil {
			return false, DKGOutput{}, nil, fmt.Errorf("error handling contribution: %v", err)
		}

		if state.ContributionsReceived == n {
			shareMessages := make([]DKGMessageTo, 0, n-1)
			for i := range indices {
				if indices[i] == ownIndex {
					share := computeShare(ownIndex, state.Coefficients)
					sliceIndex := offsetOfPlayer(ownIndex, indices)
					state.Shares[sliceIndex] = share
					state.SharesReceived++
				} else {
					share := computeShare(indices[i], state.Coefficients)
					var shareBytes [32]byte
					share.PutB32(shareBytes[:])

					shareMessages = append(shareMessages, DKGMessageTo{
						DKGMessage: DKGMessage{
							Type: DKGTypeShare,
							Data: shareBytes[:],
						},
						To: indices[i],
					})
				}
			}

			return false, DKGOutput{}, shareMessages, nil
		} else {
			return false, DKGOutput{}, nil, nil
		}
	case DKGTypeShare:
		if len(message.Data) != secp256k1.FnSizeMarshalled {
			return false, DKGOutput{}, nil, fmt.Errorf("invalid share message length: expected %v, got %v", secp256k1.FnSizeMarshalled, len(message.Data))
		}

		var share secp256k1.Fn
		share.SetB32(message.Data)

		err := DKGHandleShare(state, indices, ownIndex, from, share)
		if err != nil {
			return false, DKGOutput{}, nil, fmt.Errorf("error handling share message: %v", err)
		}

		if state.SharesReceived == n {
			return true, computeOutputs(state, indices, ownIndex), nil, nil
		} else {
			return false, DKGOutput{}, nil, nil
		}

	default:
		return false, DKGOutput{}, nil, fmt.Errorf("invalid message type %v", message.Type)
	}
}

func computeShare(index uint16, coefficients []secp256k1.Fn) secp256k1.Fn {
	indexFn := secp256k1.NewFnFromU16(index)
	l := len(coefficients)

	share := coefficients[l-1]

	if l > 1 {
		for i := l - 2; i >= 0; i-- {
			share.Mul(&share, &indexFn)
			share.Add(&share, &coefficients[i])
		}
	}

	return share
}

func verifyShare(index uint16, share secp256k1.Fn, commitments []secp256k1.Point) bool {
	indexFn := secp256k1.NewFnFromU16(index)
	check := polyEvalPoint(&indexFn, commitments)

	var expected secp256k1.Point
	expected.BaseExp(&share)

	return check.Eq(&expected)
}

func polyEvalPoint(x *secp256k1.Fn, coeffs []secp256k1.Point) secp256k1.Point {
	l := len(coeffs)
	res := coeffs[l-1]

	if l > 1 {
		for i := l - 2; i >= 0; i-- {
			res.Scale(&res, x)
			res.Add(&res, &coeffs[i])
		}
	}

	return res
}

type DKGOutput struct {
	Share        secp256k1.Fn
	PubKey       secp256k1.Point
	PubKeyShares []secp256k1.Point
}

func computeOutputs(state *DKGState, indices []uint16, ownIndex uint16) DKGOutput {
	share := secp256k1.NewFnFromU16(0)
	for i := range state.Shares {
		share.Add(&share, &state.Shares[i])
	}

	pubKey := secp256k1.NewPointInfinity()
	for i := range state.Commitments {
		pubKey.Add(&pubKey, &state.Commitments[i][0])
	}

	pubKeyShares := make([]secp256k1.Point, len(indices))
	for i := range indices {
		if indices[i] == ownIndex {
			pubKeyShares[i].BaseExp(&share)
		} else {
			index := secp256k1.NewFnFromU16(indices[i])
			pubKeyShares[i] = secp256k1.NewPointInfinity()

			for j := range state.Commitments {
				term := polyEvalPoint(&index, state.Commitments[j])
				pubKeyShares[i].Add(&pubKeyShares[i], &term)
			}
		}
	}

	return DKGOutput{Share: share, PubKey: pubKey, PubKeyShares: pubKeyShares}
}
