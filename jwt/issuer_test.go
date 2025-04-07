package jwt

import (
	"testing"

	"github.com/ooqls/go-crypto/keys"
	"github.com/ooqls/go-crypto/testutils"
	"github.com/ooqls/go-registry"
	"github.com/stretchr/testify/assert"
)

func TestIsIssuer(t *testing.T) {
	testutils.InitKeys()
//	ca, err := keys.CreateX509CA()
	//assert.Nil(t, err)

	//cert, err:= keys.CreateX509(*ca)
	//assert.Nil(t, err)

	
	registry.Set(registry.Registry{
		TokenConfiguration: registry.TokenConfiguration{
			Audience: []string{"aud", "aud2"},
			Issuer:   "issuer1",
		},
	})

	subj := "123"
	issuer := NewDefaultJwtTokenIssuer()
	issuer2 := NewJwtTokenIssuer(&registry.TokenConfiguration{
		Audience: []string{"aud3", "aud4"},
		Issuer:   "issuer2",
	}, keys.JWT())

	tokenStr, _, err := issuer.IssueToken(subj)
	assert.Nil(t, err)
	claims := TokenClaims{}
	jwtToken, err := issuer.Decrypt(tokenStr, &claims)
	assert.NotNilf(t, jwtToken, "should have gotten a jwt token")
	assert.Nilf(t, err, "should not have gotten an error from is issuer")
	assert.Truef(t, jwtToken.Valid, "token should be valid")
	assert.NotEmpty(t, claims.Issuer)

	notClaims := TokenClaims{}
	notJwtToken, err := issuer2.Decrypt(tokenStr, &notClaims)
	assert.NotNilf(t, err, "should not have gotten an error")
	assert.Falsef(t, notJwtToken.Valid, "token should not be valid")
}
