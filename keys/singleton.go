package keys

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

var m sync.Mutex = sync.Mutex{}
var jwtKey *JwtKey = nil
var cryptKey Key = nil
var caKey *X509 = nil

func InitDefault() error {
	m.Lock()
	defer m.Unlock()

	ca, err := CreateX509CA()
	if err != nil {
		return fmt.Errorf("failed to create ca: %v", err)
	}

	cert, err := CreateX509(*ca)
	if err != nil {
		return fmt.Errorf("failed to create x509: %v", err)
	}

	jwt, err := NewRSA()
	if err != nil {
		return fmt.Errorf("failed to create RSA: %v", err)
	}

	jwtKey = NewJWTKey(*jwt)
	cryptKey = cert
	caKey = ca

	return err
}

func InitCA(key, cert []byte) error {
	m.Lock()
	defer m.Unlock()

	var err error
	pemBlock := append(key, byte('\n'))
	pemBlock = append(pemBlock, cert...)
	caKey, err = ParseX509Bytes(pemBlock)
	if err != nil {
		return err
	}

	return nil
}

func InitRSA(privkey, pubkey []byte) error {
	m.Lock()
	defer m.Unlock()

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
	m.Lock()
	defer m.Unlock()

	if cryptKey == nil {
		panic("please initialize crypto before using")
	}

	return cryptKey
}

func JWT() JwtSigningKey {
	m.Lock()
	defer m.Unlock()

	if jwtKey == nil {
		panic("please initialize JWT before using")
	}

	return jwtKey
}

func CA() *X509 {
	m.Lock()
	defer m.Unlock()

	if caKey == nil {
		panic("please initialize CA before using")
	}

	return caKey
}
