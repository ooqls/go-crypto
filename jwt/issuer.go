package jwt

import (
	"github.com/ooqls/go-registry"
)

type TokenIssuer interface {
	NewToken(subj string) (*Token, error)
	IsIssuer(token *Token) bool
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

func (f *jwtTokenIssuer) NewToken(subj string) (*Token, error) {
	return NewJwtToken(subj, f.cfg.Audience, f.cfg.GenerateId(), f.cfg.Issuer)
}

func (f *jwtTokenIssuer) IsIssuer(token *Token) bool {
	claims := token.token.Claims
	iss, err := claims.GetIssuer()
	if err != nil {
		return false
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}

	audB, err := aud.MarshalJSON()
	if err != nil {
		return false
	}

	return iss == f.cfg.Issuer && string(audB) == f.cfg.Audience
}
