package authentik

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func Test_updateURL(t *testing.T) {
	assert := assert.New(t)
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "https://127.0.0.1/sso/init",
	}
	ctx := &authentikContext{
		loginDetails: loginDetails,
		url:          loginDetails.URL,
	}
	err := ctx.updateURL("/query?next=/login")
	assert.Nil(err)
	assert.Equal(ctx.url, "https://127.0.0.1/query?next=/login")

	err = ctx.updateURL("https://127.0.0.1:8888/sso/aws")
	assert.Nil(err)
	assert.Equal(ctx.url, "https://127.0.0.1:8888/sso/aws")

	// The original entry URL must be preserved for the caller (credential
	// storage, SAML cache key).
	assert.Equal(loginDetails.URL, "https://127.0.0.1/sso/init")
}
