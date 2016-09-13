package saml2aws

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateSamlConfig(t *testing.T) {

	err := ioutil.WriteFile(".credentials", []byte("[saml]"), 0666)
	assert.Nil(t, err)

	sharedCreds := &CredentialsProvider{".credentials", "saml"}

	err = sharedCreds.Save("testid", "testsecret", "testtoken")
	assert.Nil(t, err)

	os.Remove(".credentials")
}
