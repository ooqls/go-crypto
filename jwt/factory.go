package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ooqls/go-registry"
)

type TokenIssuer interface {
	NewToken(subj string) (string, *time.Time, error)
	IsIssuer(token *jwt.Token) bool
}

func NewJwtTokenIssuer(cfg *registry.TokenConfiguration) TokenIssuer {
	return &jwtTokenIssuer{
		cfg: cfg,
	}
}

func NewDefaultJwtTokenIssuer() TokenIssuer {
	r := registry.Get()
	return &jwtTokenIssuer{
		cfg: &r.TokenConfiguration,
	}
}

type jwtTokenIssuer struct {
	cfg *registry.TokenConfiguration
}

func (f *jwtTokenIssuer) NewToken(subj string) (string, *time.Time, error) {
	return NewJwtToken(subj, f.cfg.Audience, f.cfg.GenerateId(), f.cfg.Issuer)
}

func (f *jwtTokenIssuer) IsIssuer(token *jwt.Token) bool {
	iss, err := token.Claims.GetIssuer()
	if err != nil {
		return false
	}

	aud, err := token.Claims.GetAudience()
	if err != nil {
		return false
	}

	audB, err := aud.MarshalJSON()
	if err != nil {
		return false
	}

	return iss == f.cfg.Issuer && string(audB) == f.cfg.Audience
}
