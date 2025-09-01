package main

import (
	"log"

	"github.com/ooqls/go-crypto/crypto"
)

func main() {
	password := "123456"
	salt, err := crypto.GenerateSalt()
	if err != nil {
		panic(err)
	}

	salt2, err := crypto.GenerateSalt()

	key, err := crypto.DeriveAESGCMKey(password, salt)
	if err != nil {
		panic(err)
	}

	key2, err := crypto.DeriveAESGCMKey(password, salt2)
	data := []byte("hello world")

	encrypted, err := crypto.AESGCMEncryptWithKey(key, salt, data)
	if err != nil {
		panic(err)
	}

	decrypted, err := crypto.AESGCMDecryptWithKey(key2, encrypted)
	if err != nil {
		panic(err)
	}

	log.Printf("%s", string(decrypted))

}
