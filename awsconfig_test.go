package saml2aws

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateSamlConfig(t *testing.T) {

	sharedCreds := &CredentialsProvider{".credentials", "saml"}

	err := sharedCreds.Save("testid", "testsecret", "testtoken")
	assert.Nil(t, err)

	os.Remove(".credentials")
}
