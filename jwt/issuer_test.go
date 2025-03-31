package jwt

import (
	"testing"

	"github.com/ooqls/go-crypto/testutils"
	"github.com/ooqls/go-registry"
	"github.com/stretchr/testify/assert"
)

func TestIsIssuer(t *testing.T) {
	testutils.InitKeys()
	registry.Set(registry.Registry{
		TokenConfiguration: registry.TokenConfiguration{
			Audience: []string{"aud", "aud2"},
		},
	})

	subj := "123"
	issuer := NewDefaultJwtTokenIssuer()

	_, token, err := issuer.IssueToken(subj, []string{"aud"})
	assert.Nil(t, err)
	assert.True(t, issuer.IsIssuer(token))


	_, _, errInvalid := issuer.IssueToken(subj, []string{"invalid_aud"})
	assert.NotNilf(t, errInvalid, "expected error, got nil")
}
