package frost_test

import (
	"fmt"
	"sort"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DKG", func() {
	Context("honest online nodes", func() {
		It("should produce a valid shared key", func() {
			n := 10
			t := 5

			indices := sequentialIndices(n)
			context := [32]byte{}
			copy(context[:], []byte("context"))

			players := createDKGPlayers(indices, t, context)

			outputs := executeDKG(players)
			sort.Slice(outputs, func(i, j int) bool { return outputs[i].index < outputs[j].index })

			shares := make([]shamir.Share, 0, len(outputs))
			for i := range outputs {
				Expect(outputs[i].err).To(BeNil())

				shares = append(shares, shamir.Share{Index: secp256k1.NewFnFromU16(outputs[i].index), Value: outputs[i].output.Share})
			}

			Expect(shamirutil.SharesAreConsistent(shares, t)).To(BeTrue())

			var expectedPubKey secp256k1.Point
			privKey := shamir.Open(shares)
			expectedPubKey.BaseExp(&privKey)

			expectedPubKeyShares := make([]secp256k1.Point, n)
			for i := range shares {
				expectedPubKeyShares[i].BaseExp(&shares[i].Value)
			}

			for i := range outputs {
				Expect(outputs[i].output.PubKey.Eq(&expectedPubKey)).To(BeTrue())

				for j := range outputs[i].output.PubKeyShares {
					Expect(outputs[i].output.PubKeyShares[j].Eq(&expectedPubKeyShares[j])).To(BeTrue())
				}
			}
		})
	})
})

type dkgMessage struct {
	from, to uint16
	msg      frost.DKGMessage
}

type dkgRingBuffer struct {
	buf              []dkgMessage
	front, back, cap int
	full             bool
}

func newDKGRingBuffer(cap int) dkgRingBuffer {
	return dkgRingBuffer{
		buf:   make([]dkgMessage, cap),
		front: 0,
		back:  0,
		cap:   cap,
	}
}

func (rb *dkgRingBuffer) push(m dkgMessage) {
	if rb.full {
		panic("ring buffer is full")
	}

	rb.buf[rb.back] = m
	rb.back = (rb.back + 1) % rb.cap

	if rb.back == rb.front {
		rb.full = true
	}
}

func (rb *dkgRingBuffer) pop() dkgMessage {
	if rb.front == rb.back && !rb.full {
		panic("pop from empty ring buffer")
	}

	rb.full = false

	m := rb.buf[rb.front]
	rb.front = (rb.front + 1) % rb.cap
	return m
}

type dkgPlayer struct {
	index   uint16
	indices []uint16
	t       int
	context [32]byte
	state   frost.DKGState

	aborted bool
}

func createDKGPlayers(indices []uint16, t int, context [32]byte) []dkgPlayer {
	players := make([]dkgPlayer, len(indices))

	for i := range players {
		players[i] = dkgPlayer{
			index:   indices[i],
			indices: indices,
			t:       t,
			context: context,
			state:   frost.NewEmptyDKGState(len(indices), t),

			aborted: false,
		}
	}

	return players
}

type dkgSimOutput struct {
	index  uint16
	output frost.DKGOutput
	err    error
}

func executeDKG(players []dkgPlayer) []dkgSimOutput {
	msgQueue := newDKGRingBuffer(2 * len(players) * (len(players) - 1))

	for i := range players {
		msg := frost.DKGStart(&players[i].state, players[i].indices, players[i].t, players[i].index, players[i].context)
		for j := range players {
			if players[i].index != players[j].index {
				msgQueue.push(dkgMessage{
					from: players[i].index,
					to:   players[j].index,
					msg:  msg,
				})
			}
		}
	}

	outputs := make([]dkgSimOutput, 0, len(players))
	for {
		m := msgQueue.pop()

		var player *dkgPlayer = nil
		for i := range players {
			if players[i].index == m.to {
				player = &players[i]
				break
			}
		}
		if player == nil {
			panic(fmt.Sprintf("message addressed to player that does not exist: %v", m.to))
		}

		if player.aborted {
			continue
		}

		done, output, newMessages, err := frost.DKGHandleMessage(&player.state, player.index, player.indices, player.t, player.context, m.msg, m.from)

		if err != nil {
			player.aborted = true
			outputs = append(outputs, dkgSimOutput{index: player.index, output: frost.DKGOutput{}, err: err})
		}

		if newMessages != nil {
			for i := range newMessages {
				msgQueue.push(dkgMessage{
					from: player.index,
					to:   newMessages[i].To,
					msg:  newMessages[i].DKGMessage,
				})
			}
		}

		if done {
			outputs = append(outputs, dkgSimOutput{index: player.index, output: output, err: nil})
		}

		if len(outputs) == len(players) {
			return outputs
		}
	}
}
