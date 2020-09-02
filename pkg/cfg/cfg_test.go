package cfg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const throwAwayConfig = "example/gossamer3.test.yml"

func TestNewConfigManagerNew(t *testing.T) {

	cfgm, err := NewConfigManager("example/gossamer3.yml")
	require.Nil(t, err)

	require.NotNil(t, cfgm)
}

func TestNewConfigManagerLoad(t *testing.T) {

	cfgm, err := NewConfigManager("example/gossamer3.yml")
	require.Nil(t, err)

	require.NotNil(t, cfgm)

	idpAccount, err := cfgm.LoadIDPAccount("test123")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		Name:                 "test123",
		URL:                  "https://id.whatever.com",
		Username:             "abc@whatever.com",
		Provider:             "keycloak",
		MFA:                  "sms",
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		SessionDuration:      3600,
		Profile:              "saml",
	}, idpAccount)

	idpAccount, err = cfgm.LoadIDPAccount("")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		Name:                 DefaultName,
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		SessionDuration:      DefaultSessionDuration,
		Profile:              DefaultProfile,
	}, idpAccount)
}

func TestNewConfigManagerSave(t *testing.T) {

	cfgm, err := NewConfigManager(throwAwayConfig)
	require.Nil(t, err)

	err = cfgm.SaveIDPAccount(&IDPAccount{
		Name:     "testing2",
		URL:      "https://id.whatever.com",
		MFA:      "none",
		Provider: "keycloak",
		Username: "abc@whatever.com",
		Profile:  "saml",
	})
	require.Nil(t, err)
	idpAccount, err := cfgm.LoadIDPAccount("testing2")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{
		Name:                 DefaultName,
		URL:                  "https://id.whatever.com",
		Username:             "abc@whatever.com",
		Provider:             "keycloak",
		MFA:                  "none",
		SessionDuration:      DefaultSessionDuration,
		AmazonWebservicesURN: DefaultAmazonWebservicesURN,
		Profile:              DefaultProfile,
	}, idpAccount)

	os.Remove(throwAwayConfig)

}
