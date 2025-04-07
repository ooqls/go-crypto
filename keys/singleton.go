package keys

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

var jwtKey *JwtKey = nil
var cryptKey Key = nil

var defaultKeyPath string = "/keys/rsa_key.pem"
var defaultPubPath string = "/keys/rsa_key.pub"

func InitDefault() error {
	privKeyB, err := os.ReadFile(defaultKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", defaultKeyPath, err)
	}

	pubKeyB, err := os.ReadFile(defaultPubPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", defaultPubPath, err)
	}

	err = InitRSA(privKeyB, pubKeyB)
	if err != nil {
		return fmt.Errorf("failed to init RSA: %v", err)
	}

	err = InitJwt(privKeyB, pubKeyB)
	if err != nil {
		return fmt.Errorf("failed to init JWT: %v", err)
	}


	return err
}

func InitRSA(privkey, pubkey []byte) error {
	rsakey, err := ParseRSA(privkey, pubkey)
	if err != nil {
		return err
	}

	cryptKey = rsakey
	return nil
}

func InitJwt(privKey []byte, pubKey []byte) error {
	m.Lock()
	defer m.Unlock()

	l.Info("parsing keys", zap.ByteString("priv", privKey), zap.ByteString("pub", pubKey))
	rsakey, err := ParseRSA(privKey, pubKey)
	if err != nil {
		return err
	}

	jwtKey = &JwtKey{
		rsakey: *rsakey,
	}

	return nil
}

func Crypto() Key {
	if cryptKey == nil {
		panic("please initialize secure key before using")
	}

	return cryptKey
}

func JWT() JwtSigningKey {
	if jwtKey == nil {
		panic("please initialize secure key before using")
	}

	return jwtKey
}
