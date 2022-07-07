package frost

import "crypto/sha256"

// NOTE: This funcionality already exists in github.com/btcsuite/btcd. The
// reason we don't want to use it is because that code base has caused annoying
// dependency errors in the past. It is probably ok to have the functionality
// duplicated here because it is very simple and it is also based on the
// specification of BIP-340, which is not likely to change.

var tagHash = sha256.Sum256([]byte("BIP0340/challenge"))

func taggedHash(msgs ...[]byte) []byte {
	// h = sha256(sha256(tag) || sha256(tag) || msg)
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])

	for _, msg := range msgs {
		h.Write(msg)
	}

	taggedHash := h.Sum(nil)

	return taggedHash
}
