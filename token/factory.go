package token

import "github.com/braumsmilk/go-registry"

type TokenFactory interface {
	NewToken(subj string) (string, error)
}

func NewJwtTokenFactory() TokenFactory {
	r := registry.Get()
	return &jwtTokenFactory{
		cfg: &r.TokenConfiguration,
	}
}

type jwtTokenFactory struct {
	cfg *registry.TokenConfiguration
}

func (f *jwtTokenFactory) NewToken(subj string) (string, error) {
	return NewJwtToken(subj, f.cfg.Audience, f.cfg.GenerateId(), f.cfg.Issuer)
}
