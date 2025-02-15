package crypto

import (
	"errors"
	"fmt"
	"time"

	"github.com/braumsmilk/go-crypto/keys"
	"github.com/golang-jwt/jwt/v5"
)

var ErrExpiredToken error = errors.New("expired token")

// audeience is the thing we are trying to authenticate against ( eg. chat.io )
// issuer is the thing that issued the token ( eg. auth.io )
// id is the identifier of the token
// sub is the subject of the token ( eg. user id )
// exp is the expiration time of the token
func NewJwtToken(subj, aud, id, issuer string) (string, error) {

	c := jwt.MapClaims{
		"sub": subj,
		"aud": aud,
		"id":  id,
		"iss": issuer,
		"exp": jwt.NewNumericDate(time.Now().Add(1000 * time.Second)),
		"isd": jwt.NewNumericDate(time.Now()),
	}
	// c.ExpiresAt = int64(timeparse.UnixSeconds() + cfg.ValidityDurationSeconds)

	token, err := keys.GetJwtKey().Sign(c)
	if err != nil {
		return "", fmt.Errorf("failed to sign claim: %v", err)
	}

	return token, nil
}

func DecryptJwtToken(tokenstr string) (*jwt.Token, error) {
	key := keys.GetJwtKey()
	jwtToken, err := key.Decrypt(tokenstr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %v", err)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claim type")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("invalid expiration date: %v", err)
	}

	if exp.Before(time.Now()) {
		return nil, ErrExpiredToken
	}

	return jwtToken, nil
}
