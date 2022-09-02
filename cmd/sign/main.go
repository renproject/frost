package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("expected %v privkey hash\n", os.Args[0])
		return
	}

	privKeyHex := os.Args[1]
	msgHashHex := os.Args[2]

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		panic(err)
	}
	if len(privKeyBytes) != 32 {
		panic(fmt.Sprintf("unexpected private key bytes length: %v", len(privKeyBytes)))
	}

	msgHashBytes, err := hex.DecodeString(msgHashHex)
	if err != nil {
		panic(err)
	}
	if len(msgHashBytes) != 32 {
		panic(fmt.Sprintf("unexpected message hash length: %v", len(msgHashBytes)))
	}

	var privKey secp256k1.Fn
	privKey.SetB32(privKeyBytes)

	n := 10
	t := 5
	bip340 := true

	players, aggregator, aggregatedPubKey, _, _ := createPlayers(privKey, n, t, bip340)

	var msgHash [32]byte
	copy(msgHash[:], msgHashBytes)

	sig := executeThresholdSignature(&aggregator, players, msgHash)

	if !sigIsValid(&sig, &msgHash, &aggregatedPubKey, bip340) {
		panic("invalid signature!")
	}

	sigBytes := [65]byte{}
	sig.r.PutBytes(sigBytes[0:33])
	sig.s.PutB32(sigBytes[33:65])

	sigString := hex.EncodeToString(sigBytes[:])

	fmt.Printf("signature hex string: %v\n", sigString)
}

type player struct {
	state        frost.State
	index        uint16
	n, t         int
	privKeyShare secp256k1.Fn
	pubKey       secp256k1.Point
	bip340       bool

	nonce frost.Nonce
}

func (p *player) handle(m message) frost.Message {
	msg, err := frost.HandleMessage(m.msg, &p.state, p.index, &p.privKeyShare, &p.pubKey, p.n, p.t, m.from == 0, p.bip340)
	if err != nil {
		panic(err)
	}

	return msg
}

type sa struct {
	params           frost.InstanceParameters
	aggregatedPubKey secp256k1.Point
	bip340           bool

	state frost.SAState
}

func (s *sa) handle(m message) (bool, secp256k1.Point, secp256k1.Fn, bool, frost.Message) {
	done, r, z, newMsg, msg, err := frost.SAHandleMessage(m.msg, m.from, &s.state, &s.aggregatedPubKey, s.params, s.bip340)
	if err != nil {
		panic(err)
	}

	return done, r, z, newMsg, msg
}

type message struct {
	from, to uint16
	msg      frost.Message
}

type ringBuffer struct {
	buf              []message
	front, back, cap int
	full             bool
}

func newRingBuffer(cap int) ringBuffer {
	return ringBuffer{
		buf:   make([]message, cap),
		front: 0,
		back:  0,
		cap:   cap,
	}
}

func (rb *ringBuffer) push(m message) {
	if rb.full {
		panic("ring buffer is full")
	}

	rb.buf[rb.back] = m
	rb.back = (rb.back + 1) % rb.cap

	if rb.back == rb.front {
		rb.full = true
	}
}

func (rb *ringBuffer) pop() message {
	if rb.front == rb.back && !rb.full {
		panic("pop from empty ring buffer")
	}

	rb.full = false

	m := rb.buf[rb.front]
	rb.front = (rb.front + 1) % rb.cap
	return m
}

type signature struct {
	r secp256k1.Point
	s secp256k1.Fn
}

func createPlayers(privKey secp256k1.Fn, n, t int, bip340 bool) ([]player, sa, secp256k1.Point, frost.InstanceParameters, []uint16) {
	indices := sequentialIndices(n)
	_, aggregatedPubKey, privKeyShares, pubKeyShares := createDistributedKey(privKey, indices, t, bip340)

	players := make([]player, n)
	for i := range players {
		players[i] = player{
			state:        frost.State{},
			index:        indices[i],
			n:            n,
			t:            t,
			privKeyShare: privKeyShares[i],
			pubKey:       aggregatedPubKey,
			bip340:       bip340,
		}
	}

	subset := randomIndexSubset(indices, t)
	params := frost.NewInstanceParameters(subset, pubKeyShares)
	aggregator := sa{
		params:           params,
		aggregatedPubKey: aggregatedPubKey,
		bip340:           bip340,

		state: frost.NewSAState(t),
	}

	return players, aggregator, aggregatedPubKey, params, subset
}

func randomIndexSubset(indices []uint16, t int) []uint16 {
	n := len(indices)
	subset := make([]uint16, n)
	copy(subset, indices)
	rand.Shuffle(n, func(i, j int) { subset[i], subset[j] = subset[j], subset[i] })

	return subset[:t]
}

func createDistributedKey(privKey secp256k1.Fn, indices []uint16, t int, bip340 bool) (secp256k1.Fn, secp256k1.Point, []secp256k1.Fn, []secp256k1.Point) {
	var pubKey secp256k1.Point
	pubKey.BaseExp(&privKey)

	// To conform to BIP0340 we need to make sure that the public key has even
	// y.
	if bip340 && !pubKey.HasEvenY() {
		privKey.Negate(&privKey)
		pubKey.Negate(&pubKey)
	}

	shares := make(shamir.Shares, len(indices))
	indicesFn := make([]secp256k1.Fn, len(indices))
	for i := range indicesFn {
		indicesFn[i] = secp256k1.NewFnFromU16(indices[i])
	}
	if err := shamir.ShareSecret(&shares, indicesFn, privKey, t); err != nil {
		panic(err)
	}

	privKeyShares := make([]secp256k1.Fn, len(indices))
	pubKeyShares := make([]secp256k1.Point, len(indices))
	for i := range shares {
		privKeyShares[i] = shares[i].Value
		pubKeyShares[i].BaseExp(&shares[i].Value)
	}

	return privKey, pubKey, privKeyShares, pubKeyShares
}

func sequentialIndices(n int) []uint16 {
	indices := make([]uint16, n)

	for i := uint16(0); i < uint16(n); i++ {
		indices[i] = i + 1
	}

	return indices
}

func executeThresholdSignature(aggregator *sa, players []player, msgHash [32]byte) signature {
	msgQueue := newRingBuffer(len(players))

	aggregator.state.Reset(msgHash)

	for _, i := range aggregator.params.Indices {
		msgQueue.push(message{
			from: 0, // We will represent the aggregator as having index 0.
			to:   i,
			msg:  frost.Message{Type: frost.TypeCommitmentRequest, Data: nil},
		})
	}

	for {
		// This assumes that there will always be a message in the queue before
		// the aggregator is able to produce a signature.
		m := msgQueue.pop()

		if m.to == 0 {

			done, r, s, haveMsg, newMsg := aggregator.handle(m)

			if done {
				return signature{r, s}
			} else if haveMsg {
				for _, i := range aggregator.params.Indices {
					msgQueue.push(message{
						from: 0,
						to:   i,
						msg:  newMsg,
					})
				}
			}
		} else {
			player := &players[m.to-1]

			newMsg := player.handle(m)
			msgQueue.push(message{from: player.index, to: 0, msg: newMsg})
		}
	}

}

func sigIsValid(sig *signature, msgHash *[32]byte, pubKey *secp256k1.Point, bip340 bool) bool {
	rBytes := make([]byte, 33)
	pubKeyBytes := make([]byte, 33)
	sig.r.PutBytes(rBytes)
	pubKey.PutBytes(pubKeyBytes)

	var e secp256k1.Fn
	var eBytes []byte
	if bip340 {
		eBytes = frost.TaggedHash(rBytes[1:], pubKeyBytes[1:], msgHash[:])
	} else {
		eBytes = frost.CHash(rBytes, pubKeyBytes, msgHash[:])
	}
	e.SetB32(eBytes)
	e.Negate(&e)

	var sG, eP, computedR secp256k1.Point
	sG.BaseExp(&sig.s)
	eP.Scale(pubKey, &e)
	computedR.Add(&sG, &eP)

	return computedR.Eq(&sig.r)
}
