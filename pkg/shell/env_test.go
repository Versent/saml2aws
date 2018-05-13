package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
)

func TestBuildEnvVars(t *testing.T) {

	expectedArray := []string{
		"AWS_ACCESS_KEY_ID=123",
		"AWS_SECRET_ACCESS_KEY=345",
		"AWS_SESSION_TOKEN=567",
		"AWS_SECURITY_TOKEN=567",
		"EC2_SECURITY_TOKEN=567",
		"AWS_PROFILE=saml",
		"AWS_DEFAULT_PROFILE=saml",
	}

	account := &cfg.IDPAccount{
		Profile: "saml",
	}

	awsCreds := &awsconfig.AWSCredentials{
		AWSAccessKey:     "123",
		AWSSecretKey:     "345",
		AWSSecurityToken: "567",
		AWSSessionToken:  "567",
	}

	assert.Equal(t, expectedArray, BuildEnvVars(awsCreds, account))
}
