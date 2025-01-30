package keys

import (
	"fmt"
	"sync"

	"github.com/braumsmilk/go-log"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var key JwtSigningKey
var m sync.Mutex = sync.Mutex{}
var o sync.Once = sync.Once{}
var l *zap.Logger = log.NewLogger("secure")

func GetJwtKey() JwtSigningKey {
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

func ParseJwtKey(privkey, pubkey []byte) (JwtSigningKey, error) {
	rsakey, err := ParseRSA(privkey, pubkey)
	if err != nil {
		return nil, err
	}

	return &JwtKey{
		rsakey: *rsakey,
	}, nil
}

func NewJWTKey(key RSAKey) *JwtKey {
	return &JwtKey{
		rsakey: key,
	}
}

type JwtKey struct {
	rsakey RSAKey
}

func (k *JwtKey) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(&k.rsakey.privkey)
}

func (k *JwtKey) Decrypt(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", t.Method)
		}

		return &k.rsakey.pubkey, nil
	})
}
