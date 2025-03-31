package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ooqls/go-crypto/keys"
)

var ErrExpiredToken error = errors.New("expired token")

// audeience is the thing we are trying to authenticate against ( eg. chat.io )
// issuer is the thing that issued the token ( eg. auth.io )
// id is the identifier of the token
// sub is the subject of the token ( eg. user id )
// exp is the expiration time of the token
// returns the token string, the jwt token struct, and any errors
func NewJwtToken(subj, id, issuer string, aud []string, jwtKey keys.JwtSigningKey) (string, *jwt.Token, error) {
	exp := time.Now().Add(1000 * time.Second)
	c := jwt.MapClaims{
		"sub": subj,
		"aud": aud,
		"id":  id,
		"iss": issuer,
		"exp": jwt.NewNumericDate(exp),
		"isd": jwt.NewNumericDate(time.Now()),
	}
	// c.ExpiresAt = int64(timeparse.UnixSeconds() + cfg.ValidityDurationSeconds)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	tokenStr, err := jwtKey.Sign(c)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign claim: %v", err)
	}

	return tokenStr, jwtToken, nil
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
