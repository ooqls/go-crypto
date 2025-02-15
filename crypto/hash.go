package crypto

import (
	"crypto/sha512"
	"hash"
)

var h hash.Hash = sha512.New()

func GetDefaultHash() hash.Hash {
	return h
}

func SetDefaultHash(newh hash.Hash) {
	h = newh
}
