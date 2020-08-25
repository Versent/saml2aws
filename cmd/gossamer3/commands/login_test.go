package commands

import (
	"testing"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/stretchr/testify/assert"
)

func TestResolveLoginDetailsWithFlags(t *testing.T) {

	commonFlags := &flags.CommonFlags{URL: "https://id.example.com", Username: "wolfeidau", MFAToken: "123456", SkipPrompt: true}
	loginFlags := &flags.LoginExecFlags{CommonFlags: commonFlags}

	idpa := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	loginDetails, err := resolveLoginDetails(idpa, loginFlags)
	loginDetails.Password = "testtestlol"

	assert.Empty(t, err)
	assert.Equal(t, &creds.LoginDetails{Username: "wolfeidau", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}, loginDetails)
}

func TestResolveRoleSingleEntry(t *testing.T) {

	adminRole := &g3.AWSRole{
		Name:         "admin",
		RoleARN:      "arn:aws:iam::456456456456:saml-provider/example-idp,arn:aws:iam::456456456456:role/admin",
		PrincipalARN: "arn:aws:iam::456456456456:role/admin,arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	awsRoles := []*g3.AWSRole{
		adminRole,
	}

	got, err := resolveRole(awsRoles, "", cfg.NewIDPAccount())
	assert.Empty(t, err)
	assert.Equal(t, got, adminRole)
}
