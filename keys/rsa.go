package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"time"
)

var rsakey *RSAKey = nil

func NewRSAKey() (*rsa.PrivateKey, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func NewRsaKeyPemBytes() ([]byte, []byte, error) {
	key, err := NewRSAKey()
	if err != nil {
		return nil, nil, err
	}

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKeyPem, publicKeyPem, nil
}

func GetRsaKey() RSAKey {
	if rsakey == nil {
		panic("please initialize secure key before using")
	}

	return *rsakey
}

func ParseRSA(privkey, pubkey []byte) (*RSAKey, error) {
	priv, err := x509.ParsePKCS1PrivateKey(privkey)
	if err != nil {
		return nil, err
	}

	pubI, err := x509.ParsePKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}

	pub, ok := pubI.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not type RSA")
	}

	r := NewRand(int64(priv.D.Int64()))

	return newRSAKey(*priv, *pub, *r), nil
}

func NewRSA() (*RSAKey, error) {
	privkey, err := NewRSAKey()
	if err != nil {
		return nil, err
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(privkey.D.Int64())))

	return newRSAKey(*privkey, privkey.PublicKey, *r), nil
}

func newRSAKey(privkey rsa.PrivateKey, pubkey rsa.PublicKey, r rand.Rand) *RSAKey {
	return &RSAKey{
		privkey: privkey,
		pubkey:  privkey.PublicKey,
		r:       r,
	}
}

type RSAKey struct {
	r       rand.Rand
	privkey rsa.PrivateKey
	pubkey  rsa.PublicKey
}

func (r *RSAKey) Encrypt(data []byte) ([]byte, error) {
	// Encrypt data
	return rsa.EncryptPKCS1v15(&r.r, &r.pubkey, data)
}

func (r *RSAKey) Decrypt(data []byte) ([]byte, error) {
	// Decrypt data
	return rsa.DecryptPKCS1v15(&r.r, &r.privkey, data)
}

func (r *RSAKey) PublicKey() (rsa.PublicKey, []byte) {
	return r.pubkey, x509.MarshalPKCS1PublicKey(&r.pubkey)
}
