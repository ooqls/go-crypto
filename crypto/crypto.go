package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
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

func NewAESGCMAlgorithm(password string, salt [SALT_SIZE]byte) Algorithm {
	return &GenericAlgorithm{
		EncryptFunc: func(data []byte) ([]byte, error) {
			return AESGCMEncrypt(password, salt, data)
		},
		DecryptFunc: func(data []byte) ([]byte, error) {
			return AESGCMDecrypt(password, data)
		},
	}
}

func NewAESGCMAlgorithmWithKey(key []byte, salt [SALT_SIZE]byte) Algorithm {
	return &GenericAlgorithm{
		EncryptFunc: func(data []byte) ([]byte, error) {
			return AESGCMEncryptWithKey(key, salt, data)
		},
		DecryptFunc: func(data []byte) ([]byte, error) {
			return AESGCMDecryptWithKey(key, data)
		},
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

func AESGCMEncrypt(password string, salt [SALT_SIZE]byte, data []byte) ([]byte, error) {
	derivedKey, err := pbkdf2.Key(sha256.New, password, salt[:], 10000, 32)
	if err != nil {
		return nil, err
	}

	return AESGCMEncryptWithKey(derivedKey, salt, data)
}

func AESGCMDecrypt(password string, data []byte) ([]byte, error) {
	salt, iv, encrypted, err := ParseAESGCM(data)
	if err != nil {
		return nil, err
	}

	derivedKey, err := pbkdf2.Key(sha256.New, password, salt[:], 10000, 32)
	if err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	decrypted, err := gcm.Open(data[:0], iv[:], encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func AESGCMEncryptWithKey(key []byte, salt [SALT_SIZE]byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := [IV_SIZE]byte{}
	rand.Read(iv[:])

	encrypted := gcm.Seal(data[:0], iv[:], data, nil)
	return EncodeAESGCM(salt, iv, encrypted)
}

func AESGCMDecryptWithKey(key, data []byte) ([]byte, error) {
	_, iv, encrypted, err := ParseAESGCM(data)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	decrypted, err := gcm.Open(nil, iv[:], encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func ParseAESGCM(data []byte) (salt [SALT_SIZE]byte, iv [IV_SIZE]byte, encrypted []byte, err error) {
	salt = [SALT_SIZE]byte{}
	iv = [IV_SIZE]byte{}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return salt, iv, encrypted, ErrInvalidData
	}

	if len(decoded) < SALT_SIZE+IV_SIZE {
		return salt, iv, encrypted, ErrDataTooShort
	}

	copy(salt[:], decoded[:SALT_SIZE])
	copy(iv[:], decoded[SALT_SIZE:SALT_SIZE+IV_SIZE])
	encrypted = decoded[SALT_SIZE+IV_SIZE:]

	return
}

func EncodeAESGCM(salt [SALT_SIZE]byte, iv [IV_SIZE]byte, encrypted []byte) ([]byte, error) {
	payload := append(salt[:], iv[:]...)
	payload = append(payload, encrypted...)

	encoded := base64.StdEncoding.EncodeToString(payload)

	return []byte(encoded), nil
}
