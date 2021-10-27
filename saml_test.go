package saml2aws

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAwsRoles(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	roles, err := ExtractAwsRoles(data)
	assert.Nil(t, err)
	assert.Len(t, roles, 2)
}

func TestExtractSessionDuration(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	duration, err := ExtractSessionDuration(data)
	assert.Nil(t, err)
	assert.Equal(t, int64(28800), duration)
}

func TestExtractDestinationURL(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	destination, err := ExtractDestinationURL(data)
	assert.Nil(t, err)
	assert.Equal(t, "https://signin.aws.amazon.com/saml", destination)
}

func TestExtractDestinationURL2(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion_no_destination.xml")
	assert.Nil(t, err)

	destination, err := ExtractDestinationURL(data)
	assert.Nil(t, err)
	assert.Equal(t, "https://signin.aws.amazon.com/saml", destination)
}
