package frost_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("frost", func() {
	n := 30
	t := n / 2

	bip340s := []bool{true, false}

	for _, bip340 := range bip340s {
		Context(fmt.Sprintf("signing with bip340 = %v", bip340), func() {
			bip340 := bip340
			It("should sign successfully", func() {
				var msgHash [32]byte
				copy(msgHash[:], "good evening")

				players, aggregator, aggregatedPubKey, _, _ := createPlayers(n, t, msgHash, bip340)

				sig := executeThresholdSignature(&aggregator, players, msgHash)

				Expect(frost.SigIsValid(&sig.r, &sig.s, &msgHash, &aggregatedPubKey, bip340)).To(BeTrue())
			})

			Context("invalid messages", func() {
				Specify("players should reject messages that have undefined message types", func() {
					t := 1
					index := uint16(1)
					state := frost.State{}
					saState := frost.NewSAState(t)
					params := frost.NewInstanceParameters([]uint16{index}, []secp256k1.Point{secp256k1.RandomPoint()})
					privKeyShare := secp256k1.RandomFn()
					pubKey := secp256k1.RandomPoint()

					for ty := 0; ty < 256; ty++ {
						ty := uint8(ty)
						if ty != frost.TypeCommitmentRequest && ty != frost.TypeContributions {
							_, err := frost.HandleMessage(frost.Message{Type: ty}, &state, index, &privKeyShare, &pubKey, nil, 10, t, true, bip340)
							Expect(err).To(HaveOccurred())
						}

						if ty != frost.TypeCommitment && ty != frost.TypeZ {
							_, _, _, _, _, err := frost.SAHandleMessage(frost.Message{Type: ty}, index, &saState, &pubKey, params, bip340)
							Expect(err).To(HaveOccurred())
						}
					}
				})

				Specify("players should reject messages that are not from the current aggregator", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, _, _, _, _ := createPlayers(n, t, msgHash, bip340)

					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						_, err := frost.HandleMessage(msg, &players[i].state, players[i].index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, false, bip340)
						Expect(err).To(HaveOccurred())
					}
				})

				Specify("players should reject duplicate commitment requests", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, _, _, _, _ := createPlayers(n, t, msgHash, bip340)

					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						_, err := frost.HandleMessage(msg, &players[i].state, players[i].index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
						if err != nil {
							panic(err)
						}
						_, err = frost.HandleMessage(msg, &players[i].state, players[i].index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
						Expect(err).To(HaveOccurred())
					}
				})

				Specify("the aggregator should reject commitments that have invalid data", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					_, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					msg := frost.Message{Type: frost.TypeCommitment, Data: nil}
					index := subset[0]

					// Incorrect data length.
					msg.Data = make([]byte, 65)
					_, _, _, _, _, err := frost.SAHandleMessage(msg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
					Expect(err).To(HaveOccurred())

					msg.Data = make([]byte, 67)
					_, _, _, _, _, err = frost.SAHandleMessage(msg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
					Expect(err).To(HaveOccurred())

					// Invalid point serialisation.
					msg.Data = make([]byte, 66)
					d, e := secp256k1.RandomPoint(), secp256k1.RandomPoint()

					e.PutBytes(msg.Data[33:66])
					_, _, _, _, _, err = frost.SAHandleMessage(msg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
					Expect(err).To(HaveOccurred())

					d.PutBytes(msg.Data[0:33])
					eBytes := msg.Data[33:66]
					for i := range eBytes {
						eBytes[i] = 0
					}
					_, _, _, _, _, err = frost.SAHandleMessage(msg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
					Expect(err).To(HaveOccurred())
				})

				Specify("the aggregator should reject messages from players not in the chosen subset", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						index := players[i].index
						if !isElementOf(index, subset) {
							response, err := frost.HandleMessage(msg, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							_, _, _, _, _, err = frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							Expect(err).To(HaveOccurred())
						}
					}
				})

				Specify("the aggregator should reject duplicate commitments", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						index := players[i].index
						if isElementOf(index, subset) {
							response, err := frost.HandleMessage(msg, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							_, _, _, _, _, err = frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							Expect(err).ToNot(HaveOccurred())
							_, _, _, _, _, err = frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							Expect(err).To(HaveOccurred())
						}
					}
				})

				Specify("players should reject invalid proposals", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					var proposalCreated bool
					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						index := players[i].index
						if isElementOf(index, subset) {
							response, err := frost.HandleMessage(msg, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							_, _, _, hasMessage, proposal, err := frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							if err != nil {
								panic(err)
							}

							if hasMessage {
								proposalCreated = true
								data := make([]byte, len(proposal.Data))
								badProposal := frost.Message{Type: frost.TypeContributions}

								// Wrong message data length.
								badProposal.Data = proposal.Data[:len(proposal.Data)-1]
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())
								badProposal.Data = append(proposal.Data, byte(0))
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())

								// Out of range index.
								copy(data, proposal.Data)
								binary.LittleEndian.PutUint16(data[32:], uint16(n+1))
								badProposal.Data = data
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())

								// Out of order index.
								copy(data, proposal.Data)
								binary.LittleEndian.PutUint16(data[32:], uint16(n))
								badProposal.Data = data
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())

								// Bad curve point data
								copy(data, proposal.Data)
								firstD := data[34:67]
								for i := range firstD {
									firstD[i] = 0
								}
								badProposal.Data = data
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())

								copy(data, proposal.Data)
								firstE := data[67:100]
								for i := range firstE {
									firstE[i] = 0
								}
								badProposal.Data = data
								_, err = frost.HandleMessage(badProposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())

								// Duplicate proposal.
								_, err = frost.HandleMessage(proposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								if err != nil {
									panic(err)
								}
								_, err = frost.HandleMessage(proposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								Expect(err).To(HaveOccurred())
							}
						}
					}

					Expect(proposalCreated).To(BeTrue())
				})

				Specify("the aggregator should reject invalid zs", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					var proposalCreated bool
					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						index := players[i].index
						if isElementOf(index, subset) {
							response, err := frost.HandleMessage(msg, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							_, _, _, hasMessage, proposal, err := frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							if err != nil {
								panic(err)
							}

							if hasMessage {
								proposalCreated = true

								zMsg, err := frost.HandleMessage(proposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
								if err != nil {
									panic(err)
								}

								// Incorrect data length.
								_, _, _, _, _, err = frost.SAHandleMessage(frost.Message{Type: frost.TypeZ, Data: make([]byte, 31)}, index, &aggregator.state, &aggregatedPubKey, params, bip340)
								Expect(err).To(HaveOccurred())
								_, _, _, _, _, err = frost.SAHandleMessage(frost.Message{Type: frost.TypeZ, Data: make([]byte, 33)}, index, &aggregator.state, &aggregatedPubKey, params, bip340)
								Expect(err).To(HaveOccurred())

								// Player not in subset.
								var badIndex uint16
								for j := range players {
									if !isElementOf(players[j].index, subset) {
										badIndex = players[j].index
									}
								}

								_, _, _, _, _, err = frost.SAHandleMessage(zMsg, badIndex, &aggregator.state, &aggregatedPubKey, params, bip340)
								Expect(err).To(HaveOccurred())

								// Duplicate z contribution.
								_, _, _, _, _, err = frost.SAHandleMessage(zMsg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
								if err != nil {
									panic(err)
								}
								_, _, _, _, _, err = frost.SAHandleMessage(zMsg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
								Expect(err).To(HaveOccurred())
							}
						}
					}

					Expect(proposalCreated).To(BeTrue())
				})

				Specify("the aggregator should reject invalid zs when computing the signature", func() {
					var msgHash [32]byte
					copy(msgHash[:], "good evening")

					players, aggregator, aggregatedPubKey, params, subset := createPlayers(n, t, msgHash, bip340)

					var proposalCreated bool
					var proposal frost.Message
					msg := frost.Message{Type: frost.TypeCommitmentRequest}
					for i := range players {
						index := players[i].index
						if isElementOf(index, subset) {
							response, err := frost.HandleMessage(msg, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							_, _, _, proposalCreated, proposal, err = frost.SAHandleMessage(response, index, &aggregator.state, &aggregatedPubKey, params, bip340)
							if err != nil {
								panic(err)
							}
						}
					}

					Expect(proposalCreated).To(BeTrue())

					var lastError error
					for i := range players {
						index := players[i].index
						if isElementOf(index, subset) {
							zMsg, err := frost.HandleMessage(proposal, &players[i].state, index, &players[i].privKeyShare, &players[i].pubKey, msgHash[:], n, t, true, bip340)
							if err != nil {
								panic(err)
							}

							// Make one of the z values invalid.
							if index == subset[0] {
								badFn := secp256k1.RandomFn()
								badFn.PutB32(zMsg.Data)
							}

							_, _, _, _, _, lastError = frost.SAHandleMessage(zMsg, index, &aggregator.state, &aggregatedPubKey, params, bip340)
						}
					}

					Expect(lastError).To(HaveOccurred())
				})
			})
		})
	}
})

func createPlayers(n, t int, msgHash [32]byte, bip340 bool) ([]player, sa, secp256k1.Point, frost.InstanceParameters, []uint16) {
	indices := sequentialIndices(n)
	_, aggregatedPubKey, privKeyShares, pubKeyShares := createDistributedKey(indices, t, bip340)

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
			msgHash:      msgHash,
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

	aggregator.state.Reset(msgHash)

	return players, aggregator, aggregatedPubKey, params, subset
}

func isElementOf(i uint16, set []uint16) bool {
	for _, elem := range set {
		if i == elem {
			return true
		}
	}
	return false
}

func randomIndexSubset(indices []uint16, t int) []uint16 {
	n := len(indices)
	subset := make([]uint16, n)
	copy(subset, indices)
	rand.Shuffle(n, func(i, j int) { subset[i], subset[j] = subset[j], subset[i] })

	return subset[:t]
}

type message struct {
	from, to uint16
	msg      frost.Message
}

type ringBuffer[T any] struct {
	buf              []T
	front, back, cap int
	full             bool
}

func newRingBuffer[T any](cap int) ringBuffer[T] {
	return ringBuffer[T]{
		buf:   make([]T, cap),
		front: 0,
		back:  0,
		cap:   cap,
	}
}

func (rb *ringBuffer[T]) push(m T) error {
	if rb.full {
		return errors.New("ring buffer is full")
	}

	rb.buf[rb.back] = m
	rb.back = (rb.back + 1) % rb.cap

	if rb.back == rb.front {
		rb.full = true
	}

	return nil
}

func (rb *ringBuffer[T]) pop() (T, error) {
	if rb.front == rb.back && !rb.full {
		return rb.buf[0], errors.New("pop from empty ring buffer")
	}

	rb.full = false

	m := rb.buf[rb.front]
	rb.front = (rb.front + 1) % rb.cap
	return m, nil
}

type signature struct {
	r secp256k1.Point
	s secp256k1.Fn
}

func executeThresholdSignature(aggregator *sa, players []player, msgHash [32]byte) signature {
	msgQueue := newRingBuffer[message](len(players))

	aggregator.state.Reset(msgHash)

	for _, i := range aggregator.params.Indices {
		err := msgQueue.push(message{
			from: 0, // We will represent the aggregator as having index 0.
			to:   i,
			msg:  frost.Message{Type: frost.TypeCommitmentRequest, Data: nil},
		})
		if err != nil {
			panic(err)
		}
	}

	for {
		// This assumes that there will always be a message in the queue before
		// the aggregator is able to produce a signature.
		m, err := msgQueue.pop()
		if err != nil {
			panic(err)
		}

		if m.to == 0 {

			done, r, s, haveMsg, newMsg := aggregator.handle(m)

			if done {
				return signature{r, s}
			} else if haveMsg {
				for _, i := range aggregator.params.Indices {
					err := msgQueue.push(message{
						from: 0,
						to:   i,
						msg:  newMsg,
					})
					if err != nil {
						panic(err)
					}
				}
			}
		} else {
			player := &players[m.to-1]

			newMsg := player.handle(m)
			err := msgQueue.push(message{from: player.index, to: 0, msg: newMsg})
			if err != nil {
				panic(err)
			}
		}
	}

}

type player struct {
	state        frost.State
	index        uint16
	n, t         int
	privKeyShare secp256k1.Fn
	pubKey       secp256k1.Point
	bip340       bool
	msgHash      [32]byte

	nonce frost.Nonce
}

func (p *player) handle(m message) frost.Message {
	msg, err := frost.HandleMessage(m.msg, &p.state, p.index, &p.privKeyShare, &p.pubKey, p.msgHash[:], p.n, p.t, m.from == 0, p.bip340)
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

func sequentialIndices(n int) []uint16 {
	indices := make([]uint16, n)

	for i := uint16(0); i < uint16(n); i++ {
		indices[i] = i + 1
	}

	return indices
}

func createDistributedKey(indices []uint16, t int, bip340 bool) (secp256k1.Fn, secp256k1.Point, []secp256k1.Fn, []secp256k1.Point) {
	privKey := secp256k1.RandomFn()

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
