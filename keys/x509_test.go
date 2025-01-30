package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX509_CreateX509(t *testing.T) {
	x509, err := CreateX509()
	assert.Nil(t, err, "should be able to create x509")
	assert.NotNil(t, x509, "should be able to create x509")
}
