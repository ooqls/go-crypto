package keys

import (
	"crypto/rsa"
	"fmt"
	"os"
	"sync"

	"github.com/braumsmilk/go-log"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var key JwtSigningKey
var m sync.Mutex = sync.Mutex{}
var o sync.Once = sync.Once{}
var l *zap.Logger = log.NewLogger("secure")

var defaultKeyPath string = "/keys/rsa_key.pem"
var defaultPubPath string = "/keys/rsa_key.pub"

func InitFromPath(privPath, pubPath string) error {
	privB, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	pubB, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("failed to read pub key path: %v", err)
	}

	return Init(privB, pubB)
}

func InitDefault() error {
	getFirstNonEmpty := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}

		return ""
	}

	filesExist := func(paths ...string) bool {
		for _, p := range paths {
			if _, err := os.Stat(p); os.IsNotExist(err) {
				return false
			}
		}

		return true
	}

	keyPath := getFirstNonEmpty(os.Getenv("RSA_KEY_PATH"), defaultKeyPath)
	pubPath := getFirstNonEmpty(os.Getenv("RSA_PUB_PATH"), defaultPubPath)

	var privKey []byte
	var pubKey []byte
	var err error
	if filesExist(keyPath, pubPath) {
		privKey, err = os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %v", err)
		}

		pubKey, err = os.ReadFile(pubPath)
		if err != nil {
			return fmt.Errorf("failed to read pub key path: %v", err)
		}
	} else {
		return fmt.Errorf("private key or pubkey path does not exist: %s, %s", keyPath, pubPath)
	}

	return Init(privKey, pubKey)
}

func Init(privKey []byte, pubKey []byte) error {
	m.Lock()
	defer m.Unlock()

	l.Info("parsing keys", zap.ByteString("priv", privKey), zap.ByteString("pub", pubKey))

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKey)
	if err != nil {
		return fmt.Errorf("faild to parse RSA Private key: %v", err)
	}

	rsaPubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		return fmt.Errorf("failed to parse RSA public key: %v", err)
	}

	key = &JwtKey{
		key:    *rsaKey,
		pubKey: *rsaPubKey,
	}

	return nil
}

func GetKey() JwtSigningKey {
	o.Do(func() {
		m.Lock()
		defer m.Unlock()

		if key == nil {
			panic("please initialize secure key before using")
		}
	})

	return key
}

type SecureValue[T any] interface {
	Delete()
	GetValue() T
}

type JwtSigningKey interface {
	Sign(claims jwt.Claims) (string, error)
	Decrypt(token string) (*jwt.Token, error)
}

type JwtKey struct {
	key    rsa.PrivateKey
	pubKey rsa.PublicKey
}

func (k *JwtKey) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(&k.key)
}

func (k *JwtKey) Decrypt(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", t.Method)
		}

		return &k.pubKey, nil
	})
}
