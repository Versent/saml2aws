package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/flags"
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
	awsConfig := &awsconfig.AWSConfig{}
	adminRole := &saml2aws.AWSRole{
		Name:         "admin",
		RoleARN:      "arn:aws:iam::456456456456:saml-provider/example-idp,arn:aws:iam::456456456456:role/admin",
		PrincipalARN: "arn:aws:iam::456456456456:role/admin,arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	awsRoles := []*saml2aws.AWSRole{
		adminRole,
	}

	got, err := resolveRole(awsRoles, "", cfg.NewIDPAccount(), awsConfig)
	assert.Empty(t, err)
	assert.Equal(t, adminRole, got)
}
