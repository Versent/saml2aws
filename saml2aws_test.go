package saml2aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func TestProviderList_Keys(t *testing.T) {
	names := MFAsByProvider.Names()

	require.Len(t, names, 18)
}

func TestProviderList_Mfas(t *testing.T) {
	mfas := MFAsByProvider.Mfas("Ping")

	require.Len(t, mfas, 1)
}

func TestProviderInvalid(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "foo1",
	}
	_, err := NewSAMLClient(account)
	assert.ErrorContains(t, err, "Invalid provider: foo1")
}

func TestProviderAzureADInvalidMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "AzureAD",
	}
	_, err := NewSAMLClient(account)
	assert.ErrorContains(t, err, "Invalid MFA type: ")
}

func TestProviderAzureADMFA(t *testing.T) {
	account := &cfg.IDPAccount{
		Provider: "AzureAD",
		MFA:      "PhoneAppOTP",
	}
	client, err := NewSAMLClient(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{Username: "testuser", Password: "testtestlol", URL: "https://id.example.com", MFAToken: "123456"}
	err = client.Validate(loginDetails)
	assert.Nil(t, err)
}
