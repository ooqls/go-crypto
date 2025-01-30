package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/braumsmilk/go-crypto/testutils"
	"github.com/stretchr/testify/assert"
)


func getRsaKeyBytes() (priv []byte, pub []byte) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	// Encode private key to PKCS#1 ASN.1 PEM.
	priv = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		},
	)
	pubB, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}

	pub = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubB,
		},
	)

	return
}

func TestNewJwtToken(t *testing.T) {
	testutils.InitKeys()

	tkn, err := NewJwtToken("1", "aud", "id", "issuer")
	assert.Nilf(t, err, "should not error when getting new token")

	jwtToken, err := DecryptJwtToken(tkn)
	assert.Nilf(t, err, "should not fail to decrypt token")
	assert.NotNilf(t, jwtToken, "should have gotten a non-nil token")
}


