package awsconfig

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/stretchr/testify/assert"
)

func TestUpdateSamlConfig(t *testing.T) {
	os.Remove(".config")

	logrus.SetLevel(logrus.DebugLevel)

	sharedConfig := &ConfigProvider{".config", "saml"}

	exist, err := sharedConfig.ConfigExists()
	assert.Nil(t, err)
	assert.True(t, exist)

	awsConfig := &AWSConfig{
		AWSAccessKey:     "testid",
		AWSSecretKey:     "testsecret",
		AWSSessionToken:  "testtoken",
		AWSSecurityToken: "testtoken",
		RoleARN: "arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	err = sharedConfig.Save(awsConfig)
	assert.Nil(t, err)

	awsConfig, err = sharedConfig.Load()
	assert.Nil(t, err)
	assert.Equal(t, "testid", awsConfig.AWSAccessKey)
	assert.Equal(t, "testsecret", awsConfig.AWSSecretKey)
	assert.Equal(t, "testtoken", awsConfig.AWSSessionToken)
	assert.Equal(t, "arn:aws:iam::456456456456:saml-provider/example-idp", awsConfig.RoleARN)

	os.Remove(".config")
}
