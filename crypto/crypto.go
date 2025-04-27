package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/ooqls/go-crypto/keys"
	"github.com/ooqls/go-log"
	"go.uber.org/zap"
)

var l *zap.Logger = log.NewLogger("crypto")

type EncryptedData []byte

type DecryptedData []byte

type Algorithm interface {
	Encrypt(data []byte) (EncryptedData, error)
	Decrypt(data EncryptedData) (DecryptedData, error)
}

type GenericAlgorithm struct {
	EncryptFunc func(data []byte) ([]byte, error)
	DecryptFunc func(data []byte) ([]byte, error)
}

func (g *GenericAlgorithm) Encrypt(data []byte) (EncryptedData, error) {
	return g.EncryptFunc(data)
}

func (g *GenericAlgorithm) Decrypt(data EncryptedData) (DecryptedData, error) {
	return g.DecryptFunc(data)
}

func NewBase64Algorithm() Algorithm {
	return &GenericAlgorithm{
		EncryptFunc: Encrypt,
		DecryptFunc: Decrypt,
	}
}

func NewRsaAlgorithm() Algorithm {
	return &GenericAlgorithm{
		EncryptFunc: RSAEncrypt,
		DecryptFunc: RSADecrypt,
	}
}

func NewDefaultAlgorithm() Algorithm {
	return &GenericAlgorithm{
		EncryptFunc: func(data []byte) ([]byte, error) {
			return EncryptedData(data), nil
		},
		DecryptFunc: func(data []byte) ([]byte, error) {
			return DecryptedData(data), nil
		},
	}
}

func Encrypt(data []byte) ([]byte, error) {
	return EncryptedData([]byte(base64.StdEncoding.EncodeToString(data))), nil
}

func Decrypt(data []byte) ([]byte, error) {
	strData := fmt.Sprintf("%b", data)
	l.Info("got string data", zap.String("data", strData))
	dec, err := base64.StdEncoding.DecodeString(strData)
	return DecryptedData(dec), err
}

func RSAEncrypt(data []byte) ([]byte, error) {
	keys := keys.RSA()
	enc, err := keys.Encrypt(data)
	if err != nil {
		return nil, err
	}

	return EncryptedData(enc), nil
}

func RSADecrypt(data []byte) ([]byte, error) {
	keys := keys.RSA()
	dec, err := keys.Decrypt([]byte(data))
	if err != nil {
		return nil, err
	}

	return DecryptedData(dec), nil
}
