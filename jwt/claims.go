package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	// user of this token
	Subject string

	// target audience for this token
	Audience string

	// identifier of this token
	Id string

	// who created this token
	Issuer string

	// token group is a way of invalidating groups of tokens in case a token is compromised
	Grp string

	// expiration time of this token
	ExpTime jwt.NumericDate

	// the time it was issued
	IssuedDate jwt.NumericDate

	LastRequest jwt.NumericDate
}

func NewTokenClaims(c jwt.MapClaims) (*TokenClaims, error) {
	aud, err := c.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("failed to get audience: %v", err)
	}

	subj, err := c.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("failed to get subject: %v", err)
	}

	id, ok := c["id"]
	if !ok {
		return nil, fmt.Errorf("could not get id from claims")
	}

	iss, err := c.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %v", err)
	}

	exp, err := c.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get exp time: %v", err)
	}

	grp, ok := c["grp"]
	if !ok {
		return nil, fmt.Errorf("failed to get group")
	}

	clm := TokenClaims{
		Subject:  subj,
		Audience: aud[0],
		Id:       id.(string),
		Issuer:   iss,
		Grp:      grp.(string),
		ExpTime:  *exp,
	}

	return &clm, nil
}
