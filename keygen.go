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

	Step        uint8
	Commitments map[uint16][]secp256k1.Point
	Shares      map[uint16]secp256k1.Fn
}

func NewEmptyDKGState(n, t int) DKGState {
	coefficients := make([]secp256k1.Fn, t)

	commitments := make(map[uint16][]secp256k1.Point, n)
	shares := make(map[uint16]secp256k1.Fn, n)

	return DKGState{
		Coefficients: coefficients,

		Commitments: commitments,
		Shares:      shares,
	}
}

func DKGStart(state *DKGState, t int, ownIndex uint16, context [32]byte) DKGMessage {
	state.Step = 1
	for index := range state.Commitments {
		delete(state.Commitments, index)
	}
	for index := range state.Shares {
		delete(state.Shares, index)
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

	state.Commitments[ownIndex] = commitments

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

func DKGHandleContribution(state *DKGState, context [32]byte, from uint16, commitments []secp256k1.Point, proof Proof) error {
	if _, ok := state.Commitments[from]; ok {
		return errors.New("already handled commitments from player")
	}

	if !DKGCheckContribution(from, context, &commitments[0], proof) {
		return errors.New("invalid proof")
	}

	state.Commitments[from] = commitments

	return nil
}

func DKGHandleShare(state *DKGState, ownIndex, from uint16, share secp256k1.Fn) error {
	commitments, ok := state.Commitments[from]
	if !ok {
		return errors.New("share received before commitments")
	}

	if _, ok := state.Shares[from]; ok {
		return errors.New("already received share from player")
	}

	if !verifyShare(ownIndex, share, commitments) {
		return errors.New("invalid share")
	}

	state.Shares[from] = share

	return nil
}

func DKGHandleMessage(state *DKGState, ownIndex uint16, indices []uint16, t int, context [32]byte, message DKGMessage, from uint16) (bool, DKGOutput, []DKGMessageTo, error) {
	n := len(indices)

	switch message.Type {
	case DKGTypeContribution:
		if state.Step != 1 {
			return false, DKGOutput{}, nil, nil
		}

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

		err = DKGHandleContribution(state, context, from, commitments, proof)
		if err != nil {
			return false, DKGOutput{}, nil, fmt.Errorf("error handling contribution: %v", err)
		}

		if len(state.Commitments) == n {
			return transitionToStep2(state, ownIndex, indices)
		} else {
			return false, DKGOutput{}, nil, nil
		}
	case DKGTypeShare:
		if len(message.Data) != secp256k1.FnSizeMarshalled {
			return false, DKGOutput{}, nil, fmt.Errorf("invalid share message length: expected %v, got %v", secp256k1.FnSizeMarshalled, len(message.Data))
		}

		var share secp256k1.Fn
		share.SetB32(message.Data)

		err := DKGHandleShare(state, ownIndex, from, share)
		if err != nil {
			return false, DKGOutput{}, nil, fmt.Errorf("error handling share message: %v", err)
		}

		if state.Step == 2 && len(state.Shares) == len(state.Commitments) {
			return true, computeOutputs(state, indices, ownIndex), nil, nil
		} else {
			return false, DKGOutput{}, nil, nil
		}

	default:
		return false, DKGOutput{}, nil, fmt.Errorf("invalid message type %v", message.Type)
	}
}

func DKGHandleTimeout(state *DKGState, ownIndex uint16, indices []uint16, t int) (bool, DKGOutput, []DKGMessageTo, error) {
	if state.Step != 1 {
		return false, DKGOutput{}, nil, nil
	}

	if state.Step == 1 && len(state.Commitments) < t {
		return false, DKGOutput{}, nil, fmt.Errorf("timeout before obtaining sufficient commitments: needed at least %v, got %v", t, len(state.Commitments))
	}

	return transitionToStep2(state, ownIndex, indices)
}

func transitionToStep2(state *DKGState, ownIndex uint16, indices []uint16) (bool, DKGOutput, []DKGMessageTo, error) {
	shareMessages := make([]DKGMessageTo, 0, len(state.Commitments)-1)
	for index := range state.Commitments {
		if index == ownIndex {
			share := computeShare(ownIndex, state.Coefficients)
			state.Shares[ownIndex] = share
		} else {
			share := computeShare(index, state.Coefficients)
			var shareBytes [32]byte
			share.PutB32(shareBytes[:])

			shareMessages = append(shareMessages, DKGMessageTo{
				DKGMessage: DKGMessage{
					Type: DKGTypeShare,
					Data: shareBytes[:],
				},
				To: index,
			})
		}
	}

	state.Step = 2

	if len(state.Shares) == len(state.Commitments) {
		return true, computeOutputs(state, indices, ownIndex), nil, nil
	}

	return false, DKGOutput{}, shareMessages, nil
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
	for _, s := range state.Shares {
		share.Add(&share, &s)
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

			for _, commitments := range state.Commitments {
				term := polyEvalPoint(&index, commitments)
				pubKeyShares[i].Add(&pubKeyShares[i], &term)
			}
		}
	}

	return DKGOutput{Share: share, PubKey: pubKey, PubKeyShares: pubKeyShares}
}
