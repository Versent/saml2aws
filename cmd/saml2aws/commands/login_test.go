package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws"
)

func TestResolveLoginDetailsWithFlags(t *testing.T) {

	loginFlags := &LoginFlags{Hostname: "id.example.com", Username: "wolfeidau", Password: "testtestlol", SkipPrompt: true}

	loginDetails := &saml2aws.LoginDetails{Hostname: "id.example.com", Username: ""}

	err := resolveLoginDetails(loginDetails, loginFlags)

	assert.Empty(t, err)
	assert.Equal(t, loginDetails, &saml2aws.LoginDetails{Username: "wolfeidau", Password: "testtestlol", Hostname: "id.example.com"})
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
