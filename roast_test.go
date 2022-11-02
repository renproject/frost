package frost_test

import (
	"errors"
	"fmt"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ROAST", func() {
	Context("all nodes honest and online", func() {
		FIt("should sign successfully", func() {
			n := 10
			t := 5
			bip340 := false

			sigHash := [32]byte{}
			copy(sigHash[:], "sign me please")

			_, pubKey, indices, players := createRoastPlayers(n, t, sigHash, bip340)

			outputs := simulateRoast(players, indices, sigHash)

			for _, output := range outputs {
				Expect(output.err).ToNot(HaveOccurred())

				Expect(frost.SigIsValid(&output.r, &output.s, &sigHash, &pubKey, bip340)).To(BeTrue())
			}
		})
	})
})

type roastPlayer struct {
	state  frost.RoastState
	params frost.Parameters
	done   bool
}

func createRoastPlayers(n, t int, sigHash [32]byte, bip340 bool) (secp256k1.Fn, secp256k1.Point, []uint16, []roastPlayer) {
	indices := sequentialIndices(n)
	privKey, pubKey, privKeyShares, pubKeyShares := createDistributedKey(indices, t, bip340)

	pubKeySharesMap := make(map[uint16]secp256k1.Point, n)
	for i := range pubKeyShares {
		pubKeySharesMap[indices[i]] = pubKeyShares[i]
	}

	players := make([]roastPlayer, n)
	for i := range players {
		params := frost.Parameters{
			N:      n,
			T:      t,
			BIP340: bip340,

			OwnIndex:     indices[i],
			PrivKeyShare: privKeyShares[i],
			PubKeyShares: pubKeySharesMap,
			PubKey:       pubKey,
		}

		players[i] = roastPlayer{
			state:  frost.NewRoastState(n, t, indices, sigHash),
			params: params,
			done:   false,
		}
	}

	return privKey, pubKey, indices, players
}

type roastSimOutput struct {
	index uint16
	r     secp256k1.Point
	s     secp256k1.Fn
	err   error
}

func simulateRoast(players []roastPlayer, indices []uint16, sigHash [32]byte) []roastSimOutput {
	n := players[0].params.N
	t := players[0].params.T
	msgQueue := newRingBuffer[message](t*(n-t) + (n-t)*(n-1+t))

	for i := range players {
		msg := frost.RoastStart(&players[i].state, players[i].params)

		addToQueue(&msgQueue, msg, players[i].params.OwnIndex, indices)
	}

	numCompleted := 0
	simOutputs := make([]roastSimOutput, len(players))

	for numCompleted != len(players) {
		msg, err := msgQueue.pop()
		if err != nil {
			for i := range simOutputs {
				if simOutputs[i].index != 0 {
					continue
				}

				simOutputs[i] = roastSimOutput{index: players[i].params.OwnIndex, err: errors.New("did not complete")}
				numCompleted++
			}

			continue
		}

		sliceIndex := msg.to - 1
		player := &players[sliceIndex]

		if player.done {
			continue
		}

		sig, newMsg := frost.RoastHandle(&player.state, player.params, sigHash, msg.msg, msg.from)

		addToQueue(&msgQueue, newMsg, player.params.OwnIndex, indices)

		if sig.Done {
			simOutputs[sliceIndex] = roastSimOutput{index: player.params.OwnIndex, r: sig.R, s: sig.S, err: nil}
			numCompleted++
		}
	}

	return simOutputs
}

func addToQueue(msgQueue *ringBuffer[message], msg frost.MessageOutput, index uint16, indices []uint16) {
	switch msg.Destination {
	case frost.DestinationTypeNone:

	case frost.DestinationTypeOne:

		msg := message{
			from: index,
			to:   msg.To,
			msg:  msg.Message,
		}

		if err := msgQueue.push(msg); err != nil {
			panic(err)
		}

	case frost.DestinationTypeSubset:

		for _, to := range msg.Subset {
			msg := message{
				from: index,
				to:   to,
				msg:  msg.Message,
			}

			if err := msgQueue.push(msg); err != nil {
				panic(err)
			}
		}

	case frost.DestinationTypeAll:

		for _, to := range indices {
			if to == index {
				continue
			}

			msg := message{
				from: index,
				to:   to,
				msg:  msg.Message,
			}

			if err := msgQueue.push(msg); err != nil {
				panic(err)
			}
		}

	default:
		panic(fmt.Sprintf("unexcpted destination type %v", msg.Destination))
	}
}
