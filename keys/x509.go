package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func CreateX509Certificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.New(rand.NewSource(time.Now().UnixNano())), 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.New(rand.NewSource(time.Now().UnixNano())), template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, privKey, nil
}

func CreateX509() (*X509, error) {
	cert, privkey, err := CreateX509Certificate()
	if err != nil {
		return nil, err
	}

	return NewX509(*cert, *privkey, *NewRand()), nil
}

func NewX509(crt x509.Certificate, privKey rsa.PrivateKey, r rand.Rand) *X509 {
	return &X509{
		crt:     crt,
		privKey: privKey,
		r:       r,
	}
}

func ParseX509(pemB []byte) (*X509, error) {

	privateKeyblock, certBlock := pem.Decode(pemB)

	priv, err := x509.ParsePKCS1PrivateKey(privateKeyblock.Bytes)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(certBlock)
	if err != nil {
		return nil, err
	}

	return &X509{
		crt:     *crt,
		privKey: *priv,
		r:       *NewRand(),
	}, nil
}

type X509 struct {
	crt     x509.Certificate
	privKey rsa.PrivateKey
	r       rand.Rand
}

func (x *X509) Encrypt(data []byte) ([]byte, error) {
	// Encrypt data
	switch x.crt.PublicKey.(type) {
	case *rsa.PublicKey:
		return x.encryptRSA(data)
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

func (x *X509) encryptRSA(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(&x.r, x.crt.PublicKey.(*rsa.PublicKey), data)
}

func (x *X509) Decrypt(data []byte) ([]byte, error) {
	switch x.crt.PublicKey.(type) {
	case *rsa.PublicKey:
		return x.decryptRSA(data)
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func (x *X509) decryptRSA(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(&x.r, &x.privKey, data)
}

func (x *X509) GetCertificate() x509.Certificate {
	return x.crt
}

func (x *X509) PublicKey() (rsa.PublicKey, []byte) {
	pubKey := x.crt.PublicKey.(*rsa.PublicKey)
	b := x509.MarshalPKCS1PublicKey(pubKey)
	return *pubKey, b
}
