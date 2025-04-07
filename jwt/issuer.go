package jwt

import (

	"github.com/golang-jwt/jwt/v5"
	"github.com/ooqls/go-crypto/keys"
	"github.com/ooqls/go-registry"
)

type TokenIssuer interface {
	IssueToken(subj string) (string, *jwt.Token, error)
	Decrypt(token string, claims jwt.Claims) (*jwt.Token, error)
	GetIssuer() string
}

func newParserValidator(cfg *registry.TokenConfiguration) (*jwt.Parser, *jwt.Validator) {
	var opts []jwt.ParserOption
	for _, aud := range cfg.Audience {
		opts = append(opts, jwt.WithAudience(aud))
	}
	opts = append(opts, jwt.WithIssuer(cfg.Issuer))
	opts = append(opts, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	p := jwt.NewParser(opts...)	
	v := jwt.NewValidator(opts...)
	return p, v
}

func NewJwtTokenIssuer(cfg *registry.TokenConfiguration, key keys.JwtSigningKey) TokenIssuer {
	p, v := newParserValidator(cfg)
	return &jwtTokenIssuer{
		key: key,
		cfg: cfg,
		parser: p,
		validator: v,
	}
}

func NewDefaultJwtTokenIssuer() TokenIssuer {
	r := registry.Get()
	p, v := newParserValidator(&r.TokenConfiguration)
	return &jwtTokenIssuer{
		key: keys.GetJwtKey(),
		cfg: &r.TokenConfiguration,
		parser: p,
		validator: v,
	}

}

type jwtTokenIssuer struct {
	key       keys.JwtSigningKey
	cfg       *registry.TokenConfiguration
	parser *jwt.Parser
	validator *jwt.Validator
}

func (f *jwtTokenIssuer) IssueToken(subj string) (string, *jwt.Token, error) {
	// Check if all audience values in the token are also in our config
	if subj == "" {
		return "", nil, ErrInvalidSubject
	}


	return NewJwtToken(subj, f.cfg.GenerateId(), f.cfg.Issuer, f.cfg.Audience, f.key)
}

func (f *jwtTokenIssuer) Decrypt(token string, claims jwt.Claims) (*jwt.Token, error) {
	jwtToken, err := f.parser.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return f.key.PublicKey(), nil
	})

	return jwtToken, err
}

func (f *jwtTokenIssuer) GetIssuer() string {
	return f.cfg.Issuer
}
