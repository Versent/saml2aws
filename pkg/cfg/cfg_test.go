package cfg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const throwAwayConfig = "example/saml2aws.test.ini"

func TestNewConfigManagerNew(t *testing.T) {

	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)

	require.NotNil(t, cfgm)
}

func TestNewConfigManagerLoad(t *testing.T) {

	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)

	require.NotNil(t, cfgm)

	idpAccount, err := cfgm.LoadIDPAccount("test123")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{URL: "https://id.whatever.com", Username: "abc@whatever.com", Provider: "keycloak", MFA: "sms"}, idpAccount)

	idpAccount, err = cfgm.LoadIDPAccount("test1234")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{}, idpAccount)
}

func TestNewConfigManagerLoadVerify(t *testing.T) {

	cfgm, err := NewConfigManager("example/saml2aws.ini")
	require.Nil(t, err)

	require.NotNil(t, cfgm)

	idpAccount, err := cfgm.LoadVerifyIDPAccount("test123")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{URL: "https://id.whatever.com", Username: "abc@whatever.com", Provider: "keycloak", MFA: "sms"}, idpAccount)

	idpAccount, err = cfgm.LoadVerifyIDPAccount("test1234")
	require.Equal(t, err, ErrIdpAccountNotFound)
	require.Nil(t, idpAccount)
}

func TestNewConfigManagerSave(t *testing.T) {

	cfgm, err := NewConfigManager(throwAwayConfig)
	require.Nil(t, err)

	err = cfgm.SaveIDPAccount("testing2", &IDPAccount{
		URL:      "https://id.whatever.com",
		MFA:      "none",
		Provider: "keycloak",
		Username: "abc@whatever.com",
	})
	require.Nil(t, err)
	idpAccount, err := cfgm.LoadVerifyIDPAccount("testing2")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{URL: "https://id.whatever.com", Username: "abc@whatever.com", Provider: "keycloak", MFA: "none"}, idpAccount)

	os.Remove(throwAwayConfig)

}
