package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws"
)

func TestResolveLoginDetails(t *testing.T) {

	loginFlags := &LoginFlags{Hostname: "id.example.com", Username: "wolfeidau", Password: "testtestlol", SkipPrompt: true}

	loginDetails, err := resolveLoginDetails("id.example.com", loginFlags)

	assert.Empty(t, err)
	assert.Equal(t, loginDetails, &saml2aws.LoginDetails{Username: "wolfeidau", Password: "testtestlol", Hostname: "id.example.com"})
}
