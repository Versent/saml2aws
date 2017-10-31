package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
)

func TestResolveLoginDetailsWithFlags(t *testing.T) {

	loginFlags := &LoginFlags{Hostname: "id.example.com", Username: "wolfeidau", Password: "testtestlol", SkipPrompt: true}

	idpa := &cfg.IDPAccount{
		Hostname: "id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	loginDetails, err := resolveLoginDetails(idpa, loginFlags)

	assert.Empty(t, err)
	assert.Equal(t, &creds.LoginDetails{Username: "wolfeidau", Password: "testtestlol", Hostname: "id.example.com"}, loginDetails)
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

	got, err := resolveRole(awsRoles, "", &LoginFlags{})
	assert.Empty(t, err)
	assert.Equal(t, got, adminRole)
}
