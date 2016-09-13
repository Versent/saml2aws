package saml2aws

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateConfig(t *testing.T) {

	config := &ConfigLoader{".aws2saml.config", "adfs"}

	username, err := config.LoadUsername()
	assert.Nil(t, err)
	assert.Equal(t, "", username)

	err = config.SaveUsername("wolfeidau@example.com")
	assert.Nil(t, err)

	username, err = config.LoadUsername()
	assert.Nil(t, err)
	assert.Equal(t, "wolfeidau@example.com", username)

	os.Remove(".aws2saml.config")
}

func TestUpdateHostnameConfig(t *testing.T) {
	config := &ConfigLoader{".aws2saml.config", "adfs"}

	hostname, err := config.LoadHostname()
	assert.Nil(t, err)
	assert.Equal(t, "", hostname)

	err = config.SaveHostname("id.example.com")
	assert.Nil(t, err)

	hostname, err = config.LoadHostname()
	assert.Nil(t, err)
	assert.Equal(t, "id.example.com", hostname)

	os.Remove(".aws2saml.config")
}
