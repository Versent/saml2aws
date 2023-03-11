package saml2aws

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExtractAwsRoles(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	roles, err := ExtractAwsRoles(data)
	assert.Nil(t, err)
	assert.Len(t, roles, 2)
}

func TestExtractSessionDuration(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	duration, err := ExtractSessionDuration(data)
	assert.Nil(t, err)
	assert.Equal(t, int64(28800), duration)
}

func TestExtractDestinationURL(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	destination, err := ExtractDestinationURL(data)
	assert.Nil(t, err)
	assert.Equal(t, "https://signin.aws.amazon.com/saml", destination)
}

func TestExtractDestinationURL2(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion_no_destination.xml")
	assert.Nil(t, err)

	destination, err := ExtractDestinationURL(data)
	assert.Nil(t, err)
	assert.Equal(t, "https://signin.aws.amazon.com/saml", destination)
}

func TestExtractMFATokenDuration(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	timeObject, err := ExtractMFATokenExpiryTime(data)

	assert.Nil(t, err)
	assert.Equal(t, "2016-09-10T02:59:39Z", timeObject.Format(time.RFC3339))
}

func TestExtractMFATokenDuration2(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion_invalid_date.xml")
	assert.Nil(t, err)

	_, err = ExtractMFATokenExpiryTime(data)
	t.Log(err)
	assert.NotNil(t, err)
}
