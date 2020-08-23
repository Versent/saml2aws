package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/pkg/cfg"
)

func TestOverrideAllFlags(t *testing.T) {

	commonFlags := &CommonFlags{
		IdpProvider:          "ADFS",
		MFA:                  "mymfa",
		SkipVerify:           true,
		URL:                  "https://id.example.com",
		Username:             "myuser",
		AmazonWebservicesURN: "urn:amazon:webservices",
		SessionDuration:      3600,
		Profile:              "saml",
	}
	idpa := &cfg.IDPAccount{
		Provider:             "Ping",
		MFA:                  "none",
		SkipVerify:           false,
		URL:                  "https://id.test.com",
		Username:             "test123",
		AmazonWebservicesURN: "urn:amazon:webservices:govcloud",
	}

	expected := &cfg.IDPAccount{
		Provider:             "ADFS",
		MFA:                  "mymfa",
		SkipVerify:           true,
		URL:                  "https://id.example.com",
		Username:             "myuser",
		AmazonWebservicesURN: "urn:amazon:webservices",
		SessionDuration:      3600,
		Profile:              "saml",
	}
	ApplyFlagOverrides(commonFlags, idpa)

	assert.Equal(t, expected, idpa)
}

func TestNoOverrides(t *testing.T) {

	commonFlags := &CommonFlags{
		IdpProvider:          "",
		MFA:                  "",
		SkipVerify:           false,
		URL:                  "",
		Username:             "",
		AmazonWebservicesURN: "",
	}
	idpa := &cfg.IDPAccount{
		Provider:             "Ping",
		MFA:                  "none",
		SkipVerify:           false,
		URL:                  "https://id.test.com",
		Username:             "test123",
		AmazonWebservicesURN: "urn:amazon:webservices:govcloud",
	}

	expected := &cfg.IDPAccount{
		Provider:             "Ping",
		MFA:                  "none",
		SkipVerify:           false,
		URL:                  "https://id.test.com",
		Username:             "test123",
		AmazonWebservicesURN: "urn:amazon:webservices:govcloud",
	}
	ApplyFlagOverrides(commonFlags, idpa)

	assert.Equal(t, expected, idpa)
}
