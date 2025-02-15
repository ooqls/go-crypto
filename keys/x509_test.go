package keys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX509_CreateX509(t *testing.T) {
	ca, err := CreateX509CA()
	assert.Nil(t, err, "should be able to create CA")
	assert.NotNil(t, ca, "should be able to create CA")

	x509, err := CreateX509(*ca)
	assert.Nil(t, err, "should be able to create x509")
	assert.NotNil(t, x509, "should be able to create x509")
	

	assert.Equal(t, ca.crt.Subject, x509.GetCertificate().Subject, "subjects should match")
	assert.Equal(t, ca.crt.Issuer, x509.GetCertificate().Issuer, "issuers should match")
	assert.Equal(t, ca.crt.NotBefore, x509.GetCertificate().NotBefore, "not before should match")
	assert.Equal(t, ca.crt.NotAfter, x509.GetCertificate().NotAfter, "not after should match")
	assert.Equal(t, ca.crt.PublicKeyAlgorithm, x509.GetCertificate().PublicKeyAlgorithm, "public key algorithms should match")
	assert.Equal(t, ca.crt.SubjectKeyId, x509.GetCertificate().SubjectKeyId, "subject key IDs should match")
	assert.Equal(t, ca.crt.AuthorityKeyId, x509.GetCertificate().AuthorityKeyId, "authority key IDs should match")
}
