package frost_test

import (
	"fmt"
	"sort"
	"time"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DKG", func() {
	Context("all nodes honest and online", func() {
		It("should produce a valid shared key", func() {
			n := 10
			t := 5

			indices := sequentialIndices(n)
			context := [32]byte{}
			copy(context[:], []byte("context"))
			step1Timeout := time.Duration(500 * time.Millisecond)

			players := createDKGPlayers(indices, t, context)

			outputs := executeDKG(players, step1Timeout)
			checkOutputs(outputs, n, t, indices)
		})
	})

	Context("all nodes honest and some offline", func() {
		It("should produce a valid shared key when less than n-t nodes are offline", func() {
			n := 10
			t := 5

			indices := sequentialIndices(n)
			context := [32]byte{}
			copy(context[:], []byte("context"))
			step1Timeout := time.Duration(500 * time.Millisecond)

			players := createDKGPlayers(indices, t, context)
			for i := 0; i < n-t; i++ {
				players[i].online = false
			}

			outputs := executeDKG(players, step1Timeout)
			checkOutputs(outputs, n, t, indices)
		})
	})
})

func checkOutputs(outputs []dkgSimOutput, n, t int, indices []uint16) {
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].index < outputs[j].index })
	outputIndices := make([]uint16, len(outputs))

	shares := make([]shamir.Share, 0, len(outputs))
	for i := range outputs {
		Expect(outputs[i].err).To(BeNil())

		shares = append(shares, shamir.Share{Index: secp256k1.NewFnFromU16(outputs[i].index), Value: outputs[i].output.Share})
		outputIndices[i] = outputs[i].index
	}

	Expect(shamirutil.SharesAreConsistent(shares, t)).To(BeTrue())

	var expectedPubKey secp256k1.Point
	privKey := shamir.Open(shares)
	expectedPubKey.BaseExp(&privKey)

	expectedPubKeyShares := make([]secp256k1.Point, n)
	cursor := 0
	for i := range expectedPubKeyShares {
		if !setContains(outputIndices, indices[i]) {
			continue
		}

		expectedPubKeyShares[i].BaseExp(&shares[cursor].Value)
		cursor++
	}

	for i := range outputs {
		Expect(outputs[i].output.PubKey.Eq(&expectedPubKey)).To(BeTrue())

		for j := range outputs[i].output.PubKeyShares {
			if !setContains(outputIndices, indices[j]) {
				continue
			}

			Expect(outputs[i].output.PubKeyShares[j].Eq(&expectedPubKeyShares[j])).To(BeTrue())
		}
	}
}

func setContains(set []uint16, elem uint16) bool {
	for i := range set {
		if set[i] == elem {
			return true
		}
	}

	return false
}

type dkgMessage struct {
	from, to uint16
	msg      frost.DKGMessage
}

func (m dkgMessage) isBufferMessage() {}

type dkgPlayer struct {
	index   uint16
	indices []uint16
	t       int
	context [32]byte
	state   frost.DKGState

	online  bool
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

			online:  true,
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

func executeDKG(players []dkgPlayer, step1Timeout time.Duration) []dkgSimOutput {
	msgQueue := newRingBuffer[dkgMessage](2 * len(players) * (len(players) - 1))
	timeout := time.After(step1Timeout)

	for i := range players {
		if players[i].online {
			msg := frost.DKGStart(&players[i].state, players[i].t, players[i].index, players[i].context)
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
	}

	outputs := make([]dkgSimOutput, 0, len(players))
	for {
		m, err := msgQueue.pop()
		if err != nil {
			<-timeout

			for i := range players {
				if players[i].online {
					done, output, newMessages, err := frost.DKGHandleTimeout(&players[i].state, players[i].index, players[i].indices, players[i].t)

					processHandleOutput(&msgQueue, &players[i], &outputs, done, output, newMessages, err)
					if simulationDone(players, outputs) {
						return outputs
					}
				}
			}
		}

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

		if player.aborted || !player.online {
			continue
		}

		done, output, newMessages, err := frost.DKGHandleMessage(&player.state, player.index, player.indices, player.t, player.context, m.msg, m.from)

		processHandleOutput(&msgQueue, player, &outputs, done, output, newMessages, err)
		if simulationDone(players, outputs) {
			return outputs
		}
	}
}

func simulationDone(players []dkgPlayer, outputs []dkgSimOutput) bool {
	numOnline := 0
	for i := range players {
		if players[i].online {
			numOnline++
		}
	}

	return len(outputs) == numOnline
}

func processHandleOutput(msgQueue *ringBuffer[dkgMessage], player *dkgPlayer, outputs *[]dkgSimOutput, done bool, output frost.DKGOutput, newMessages []frost.DKGMessageTo, err error) {
	if err != nil {
		player.aborted = true
		*outputs = append(*outputs, dkgSimOutput{index: player.index, output: frost.DKGOutput{}, err: err})
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
		*outputs = append(*outputs, dkgSimOutput{index: player.index, output: output, err: nil})
	}
}
