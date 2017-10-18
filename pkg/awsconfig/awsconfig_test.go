package awsconfig

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateSamlConfig(t *testing.T) {
	os.Remove(".credentials")

	sharedCreds := &CredentialsProvider{".credentials", "saml"}

	exist, err := sharedCreds.CredsExists()
	assert.Nil(t, err)
	assert.True(t, exist)

	err = sharedCreds.Save("testid", "testsecret", "testtoken")
	assert.Nil(t, err)

	id, secret, token, err := sharedCreds.Load()
	assert.Nil(t, err)
	assert.Equal(t, "testid", id)
	assert.Equal(t, "testsecret", secret)
	assert.Equal(t, "testtoken", token)

	os.Remove(".credentials")
}
