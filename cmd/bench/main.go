package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/pkg/profile"
	"github.com/renproject/frost"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
)

func main() {
	defer profile.Start().Stop()

	rand.Seed(time.Now().UnixNano())

	n := 3000
	t := n / 2

	indices := sequentialIndices(n)
	privKey, privKeyShares, pubKeyShares := createDistributedKey(indices, t)
	aggregatedPubKey := pubKeyPoint(privKey)

	players := make([]player, n)
	for i := range players {
		players[i] = player{
			state:        frost.State{},
			index:        indices[i],
			n:            n,
			t:            t,
			privKeyShare: privKeyShares[i],
			pubKey:       aggregatedPubKey,
		}
	}

	subset := randomIndexSubset(indices, t)
	params := frost.NewInstanceParameters(subset, pubKeyShares)
	aggregator := sa{
		params:           params,
		aggregatedPubKey: aggregatedPubKey,

		state: frost.NewSAState(t),
	}

	var msgHash [32]byte
	copy(msgHash[:], "good evening")

	thresholdSig := executeThresholdSignature(&aggregator, players, msgHash)
	if valid := thresholdSig.Verify(msgHash[:], privKey.PubKey()); !valid {
		panic("invalid signature!")
	} else {
		filename := fmt.Sprintf("%v-%v.metrics", n, t)
		reportMetrics(&aggregator, players, filename)
	}
}

func randomIndexSubset(indices []uint16, t int) []uint16 {
	n := len(indices)
	subset := make([]uint16, n)
	copy(subset, indices)
	rand.Shuffle(n, func(i, j int) { subset[i], subset[j] = subset[j], subset[i] })

	return subset[:t]
}

func reportMetrics(aggregator *sa, players []player, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}

	columns := "Player |    Upload |  Download | Sent | Received |         Time\n"
	separator := "---------------------------------------------------------------\n"
	playerStr := "%4v   | %9v | %9v | %4v |     %4v | %12v\n"

	lineLen := len(columns)
	buf := make([]byte, lineLen*(2+1+len(players)))
	remainder := buf

	copy(remainder, []byte(columns))
	remainder = remainder[lineLen:]
	copy(remainder, []byte(separator))
	remainder = remainder[lineLen:]
	copy(remainder, []byte(fmt.Sprintf(playerStr, 0, aggregator.uploaded, aggregator.downloaded, aggregator.numMsgsSent, aggregator.numMsgsReceived, aggregator.totalTime)))
	remainder = remainder[lineLen:]

	for _, player := range players {
		copy(remainder, []byte(fmt.Sprintf(playerStr, player.index, player.uploaded, player.downloaded, player.numMsgsSent, player.numMsgsReceived, player.totalTime)))
		remainder = remainder[lineLen:]
	}

	file.Write(buf)
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

func executeThresholdSignature(aggregator *sa, players []player, msgHash [32]byte) *schnorr.Signature {
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
			aggregator.metrics.recordMsgReceipt(m.msg)

			done, r, s, haveMsg, newMsg := aggregator.handle(m.msg, m.from)

			if done {
				var buf [32]byte
				rx, _, err := r.XY()
				if err != nil {
					panic(err)
				}
				var x btcec.FieldVal
				rx.PutB32(buf[:])
				x.SetBytes(&buf)

				var sBTC btcec.ModNScalar
				s.PutB32(buf[:])
				sBTC.SetBytes(&buf)

				return schnorr.NewSignature(&x, &sBTC)
			} else if haveMsg {
				for _, i := range aggregator.params.Indices {
					msgQueue.push(message{
						from: 0,
						to:   i,
						msg:  newMsg,
					})
					aggregator.metrics.recordMsgSend(newMsg)
				}
			}
		} else {
			player := &players[m.to-1]
			player.metrics.recordMsgReceipt(m.msg)

			newMsg := player.handle(m.msg)
			msgQueue.push(message{from: player.index, to: 0, msg: newMsg})
			player.metrics.recordMsgSend(newMsg)
		}
	}

}

type metrics struct {
	numMsgsSent, numMsgsReceived int
	uploaded, downloaded         int
	totalTime                    time.Duration
}

func (m *metrics) recordMsgSend(msg frost.Message) {
	m.numMsgsSent++
	m.uploaded += 2 + len(msg.Data)
}

func (m *metrics) recordMsgReceipt(msg frost.Message) {
	m.numMsgsReceived++
	m.downloaded += 2 + len(msg.Data)
}

func (m *metrics) recordHandleMsg(time time.Duration) {
	m.totalTime += time
}

type player struct {
	metrics

	state        frost.State
	index        uint16
	n, t         int
	privKeyShare secp256k1.Fn
	pubKey       secp256k1.Point

	nonce frost.Nonce
}

func (p *player) handle(msg frost.Message) frost.Message {
	start := time.Now()
	msg, err := frost.Handle(msg, &p.state, p.index, &p.privKeyShare, &p.pubKey, p.n, p.t)
	time := time.Since(start)
	if err != nil {
		panic(err)
	}

	p.metrics.recordHandleMsg(time)

	return msg
}

type sa struct {
	metrics

	params           frost.InstanceParameters
	aggregatedPubKey secp256k1.Point

	state frost.SAState
}

func (s *sa) handle(msg frost.Message, from uint16) (bool, secp256k1.Point, secp256k1.Fn, bool, frost.Message) {
	start := time.Now()
	done, r, z, newMsg, msg, err := frost.SAHandleMessage(msg, from, &s.state, &s.aggregatedPubKey, s.params)
	time := time.Since(start)
	if err != nil {
		panic(err)
	}

	s.metrics.recordHandleMsg(time)

	return done, r, z, newMsg, msg
}

func sequentialIndices(n int) []uint16 {
	indices := make([]uint16, n)

	for i := uint16(0); i < uint16(n); i++ {
		indices[i] = i + 1
	}

	return indices
}

func createDistributedKey(indices []uint16, t int) (*btcec.PrivateKey, []secp256k1.Fn, []secp256k1.Point) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	// To conform to BIP0340 we need to make sure that the public key has even
	// y.
	pubkeyBytes := privKey.PubKey().SerializeCompressed()
	if pubkeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKey.Key.Negate()
	}

	privKeyBytes := privKey.Serialize()
	var privKeyFn secp256k1.Fn
	privKeyFn.SetB32(privKeyBytes)

	shares := make(shamir.Shares, len(indices))
	indicesFn := make([]secp256k1.Fn, len(indices))
	for i := range indicesFn {
		indicesFn[i] = secp256k1.NewFnFromU16(indices[i])
	}
	if err := shamir.ShareSecret(&shares, indicesFn, privKeyFn, t); err != nil {
		panic(err)
	}

	privKeyShares := make([]secp256k1.Fn, len(indices))
	pubKeyShares := make([]secp256k1.Point, len(indices))
	for i := range shares {
		privKeyShares[i] = shares[i].Value
		pubKeyShares[i].BaseExp(&shares[i].Value)
	}

	return privKey, privKeyShares, pubKeyShares
}

func pubKeyPoint(privKey *btcec.PrivateKey) secp256k1.Point {
	var point secp256k1.Point

	bs := privKey.PubKey().SerializeUncompressed()
	var x, y secp256k1.Fp
	x.SetB32(bs[1:33])
	y.SetB32(bs[33:65])
	point.SetXY(&x, &y)

	return point
}
