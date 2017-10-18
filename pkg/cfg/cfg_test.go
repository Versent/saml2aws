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
	require.Equal(t, &IDPAccount{Hostname: "id.whatever.com", Username: "abc@whatever.com", Provider: "keycloak", MFA: "sms"}, idpAccount)

	idpAccount, err = cfgm.LoadIDPAccount("test1234")
	require.Nil(t, err)
	require.Equal(t, &IDPAccount{}, idpAccount)
}

func TestNewConfigManagerSave(t *testing.T) {

	cfgm, err := NewConfigManager(throwAwayConfig)
	require.Nil(t, err)

	err = cfgm.SaveIDPAccount("testing2", &IDPAccount{
		Hostname: "test123",
		MFA:      "none",
		Provider: "Ping",
		Username: "testetst",
	})
	require.Nil(t, err)

	os.Remove(throwAwayConfig)

}
