package tokenv1

import (
	"github.com/braumsmilk/go-registry"
	"github.com/google/uuid"
)

const RedisTokenValidityMinutes string = "token_validity_minutes"

func NewConfig(issuer, audience string) TokenConfig {
	regRedis := registry.Get().Redis

	validityHours := 12
	if regRedis.Extra != nil {
		validityMinutesVal, ok := regRedis.Extra[RedisTokenValidityMinutes]
		if ok {
			validityHours = validityMinutesVal.(int)
		}
	}

	return TokenConfig{
		ValidityHours: validityHours,
		Issuer:        issuer,
		Audience:      audience,
	}
}

type TokenConfig struct {
	Issuer        string `yaml:"issuer"`
	Audience      string `yaml:"audience"`
	ValidityHours int    `yaml:"validity_hours"`
}

func (c *TokenConfig) GenerateId() string {
	return uuid.New().String()
}
