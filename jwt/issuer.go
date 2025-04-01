package jwt

import (
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ooqls/go-crypto/keys"
	"github.com/ooqls/go-registry"
)

type TokenIssuer interface {
	IssueToken(subj string, audience []string) (string, *jwt.Token, error)
	IsIssuer(token *jwt.Token) bool
	GetIssuer() string
}

func NewJwtTokenIssuer(cfg *registry.TokenConfiguration, key keys.JwtSigningKey) TokenIssuer {
	return &jwtTokenIssuer{
		key: key,
		cfg: cfg,
	}
}

func NewDefaultJwtTokenIssuer() TokenIssuer {
	r := registry.Get()
	return &jwtTokenIssuer{
		key: keys.GetJwtKey(),
		cfg: &r.TokenConfiguration,
	}
}

type jwtTokenIssuer struct {
	key keys.JwtSigningKey
	cfg *registry.TokenConfiguration
}

func (f *jwtTokenIssuer) IssueToken(subj string, audience []string) (string, *jwt.Token, error) {
	if len(audience) == 0 {
		return "", nil, ErrInvalidAudience
	}

	if subj == "" {
		return "", nil, ErrInvalidSubject
	}
	// Check if all audience values in the token are also in our config
	for _, a := range audience {
		if !slices.Contains(f.cfg.Audience, a) {
			return "", nil, ErrInvalidAudience
		}
	}

	return NewJwtToken(subj, f.cfg.GenerateId(), f.cfg.Issuer, audience, f.key)
}

func (f *jwtTokenIssuer) IsIssuer(token *jwt.Token) bool {
	claims := token.Claims.(jwt.MapClaims)

	iss, err := claims.GetIssuer()
	if err != nil {
		return false
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}

	// Check if all audience values in the token are also in our config
	for _, a := range aud {
		if !slices.Contains(f.cfg.Audience, a) {
			return false
		}
	}

	return strings.EqualFold(iss, f.cfg.Issuer)
}

func (f *jwtTokenIssuer) GetIssuer() string {
	return f.cfg.Issuer
}