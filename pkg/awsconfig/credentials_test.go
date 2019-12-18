package awsconfig

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
)

func TestUpdateSamlCredentials(t *testing.T) {
	os.Remove(".credentials")

	logrus.SetLevel(logrus.DebugLevel)

	sharedCreds := &CredentialsProvider{".credentials", "saml"}

	exist, err := sharedCreds.CredsExists()
	assert.Nil(t, err)
	assert.True(t, exist)

	awsCreds := &AWSCredentials{
		AWSAccessKey:     "testid",
		AWSSecretKey:     "testsecret",
		AWSSessionToken:  "testtoken",
		AWSSecurityToken: "testtoken",
	}

	err = sharedCreds.Save(awsCreds)
	assert.Nil(t, err)

	awsCreds, err = sharedCreds.Load()
	assert.Nil(t, err)
	assert.Equal(t, "testid", awsCreds.AWSAccessKey)
	assert.Equal(t, "testsecret", awsCreds.AWSSecretKey)
	assert.Equal(t, "testtoken", awsCreds.AWSSessionToken)

	os.Remove(".credentials")
}
