package frost_test

import (
	"time"

	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Integration", func() {
	Context("all nodes honest and online", func() {
		It("DKG should succeed and the outputs can be used to successfully sign", func() {
			n := 10
			t := 5
			bip340 := false

			indices := sequentialIndices(n)
			context := [32]byte{}
			copy(context[:], []byte("context"))
			step1Timeout := time.Duration(500 * time.Millisecond)

			dkgPlayers := createDKGPlayers(indices, t, context)

			outputs := executeDKG(dkgPlayers, step1Timeout)
			checkOutputs(outputs, n, t, indices)

			var msgHash [32]byte
			copy(msgHash[:], "good evening")

			players, aggregator, aggregatedPubKey, _, _ := createPlayers(n, t, msgHash, bip340)

			sig := executeThresholdSignature(&aggregator, players, msgHash)

			Expect(frost.SigIsValid(&sig.r, &sig.s, &msgHash, &aggregatedPubKey, bip340)).To(BeTrue())
		})
	})
})

func createPlayersFromDKGOutputs(outputs []dkgSimOutput, indices []uint16, t int, bip340 bool) ([]player, sa, secp256k1.Point, frost.InstanceParameters, []uint16) {
	n := len(indices)
	aggregatedPubKey := outputs[0].output.PubKey
	pubKeyShares := outputs[0].output.PubKeyShares

	players := make([]player, n)
	for i := range players {
		var output dkgSimOutput
		for j := range outputs {
			if outputs[j].index == indices[i] {
				output = outputs[j]
				break
			}
		}

		players[i] = player{
			state:        frost.State{},
			index:        indices[i],
			n:            n,
			t:            t,
			privKeyShare: output.output.Share,
			pubKey:       output.output.PubKey,
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
