package browser

import (
	"testing"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func TestValidate(t *testing.T) {
	getSAMLResponse = fakeSAMLResponse
	account := &cfg.IDPAccount{
		Headless: true,
	}
	client, err := New(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{
		URL: "https://google.com/",
	}
	resp, err := client.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, resp, "foo")
}

func fakeSAMLResponse(page playwright.Page, loginDetails *creds.LoginDetails) (string, error) {
	return "foo", nil
}

func TestSigninRegex1(t *testing.T) {
	regex, err := signinRegex()
	assert.Nil(t, err)
	match := regex.MatchString("https://signin.aws.amazon.com/saml")
	assert.True(t, match)
}

func TestSigninRegexFail(t *testing.T) {
	regex, err := signinRegex()
	assert.Nil(t, err)
	match := regex.MatchString("https://google.com/")
	assert.False(t, match)
}
