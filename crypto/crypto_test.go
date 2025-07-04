package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCM_encrypt(t *testing.T) {
	password := "123456"
	data := []byte("hello world")
	var salt [SALT_SIZE]byte
	rand.Read(salt[:])
	encrypted, err := AESGCMEncrypt(password, salt, data)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := AESGCMDecrypt(password, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Fatal("decrypted data is not equal to original data")
	}
}
