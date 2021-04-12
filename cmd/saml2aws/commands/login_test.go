package commands

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/flags"
)

func TestResolveLoginDetailsWithFlags(t *testing.T) {

	commonFlags := &flags.CommonFlags{URL: "https://id.example.com", Username: "wolfeidau", Password: "testtestlol", MFAToken: "123456", SkipPrompt: true}
	loginFlags := &flags.LoginExecFlags{CommonFlags: commonFlags}

	idpa := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	loginDetails, err := resolveLoginDetails(idpa, loginFlags)

	assert.Empty(t, err)
	assert.Equal(t, &creds.LoginDetails{Username: "wolfeidau", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}, loginDetails)
}

func TestResolveRoleSingleEntry(t *testing.T) {

	adminRole := &saml2aws.AWSRole{
		Name:         "admin",
		RoleARN:      "arn:aws:iam::456456456456:saml-provider/example-idp,arn:aws:iam::456456456456:role/admin",
		PrincipalARN: "arn:aws:iam::456456456456:role/admin,arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	awsRoles := []*saml2aws.AWSRole{
		adminRole,
	}

	got, err := resolveRole(awsRoles, "", cfg.NewIDPAccount())
	assert.Empty(t, err)
	assert.Equal(t, got, adminRole)
}

func TestCredentialsToCredentialProcess(t *testing.T) {

	aws_creds := &awsconfig.AWSCredentials{
		AWSAccessKey:    "someawsaccesskey",
		AWSSecretKey:    "somesecretkey",
		AWSSessionToken: "somesessiontoken",
		Expires:         time.Date(2020, time.January, 20, 22, 50, 0, 0, time.UTC),
	}
	aws_json_expected_output := "{\"Version\":1,\"AccessKeyId\":\"someawsaccesskey\",\"SecretAccessKey\":\"somesecretkey\",\"SessionToken\":\"somesessiontoken\",\"Expiration\":\"2020-01-20T22:50:00+00:00\"}"

	json, err := CredentialsToCredentialProcess(aws_creds)
	assert.Empty(t, err)
	assert.Equal(t, aws_json_expected_output, json)
}
