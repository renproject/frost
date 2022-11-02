package xoroshiro

import (
	"encoding/binary"
	"math/bits"
)

const (
	a = 24
	b = 16
	c = 37
)

type Rng struct {
	state [2]uint64
}

func (rng *Rng) Seed(seed []byte) {
	rng.state[0] = binary.LittleEndian.Uint64(seed)
	rng.state[1] = binary.LittleEndian.Uint64(seed[8:])
}

func (rng *Rng) Uint64() uint64 {
	result := rng.state[0] + rng.state[1]

	temp := rng.state[0] ^ rng.state[1]
	rng.state[0] = bits.RotateLeft64(rng.state[0], a) ^ temp ^ (temp << b)
	rng.state[1] = bits.RotateLeft64(temp, c)

	return result
}
