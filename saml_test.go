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

func TestExtractAwsRolesFail(t *testing.T) {
	data, err := os.ReadFile("testdata/notxml.xml")
	assert.Nil(t, err)

	_, err = ExtractAwsRoles(data)
	assert.Error(t, err)
}

func TestExtractSessionDuration(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	duration, err := ExtractSessionDuration(data)
	assert.Nil(t, err)
	assert.Equal(t, int64(28800), duration)
}

func TestExtractSessionDurationFail(t *testing.T) {
	data, err := os.ReadFile("testdata/notxml.xml")
	assert.Nil(t, err)

	_, err = ExtractSessionDuration(data)
	assert.Error(t, err)
}

func TestExtractDestinationURL(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	destination, err := ExtractDestinationURL(data)
	assert.Nil(t, err)
	assert.Equal(t, "https://signin.aws.amazon.com/saml", destination)
}

func TestExtractDestinationURLFail(t *testing.T) {
	data, err := os.ReadFile("testdata/notxml.xml")
	assert.Nil(t, err)

	_, err = ExtractDestinationURL(data)
	assert.Error(t, err)
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

func TestExtractMFATokenDurationFail(t *testing.T) {
	data, err := os.ReadFile("testdata/notxml.xml")
	assert.Nil(t, err)

	_, err = ExtractMFATokenExpiryTime(data)

	assert.Error(t, err)
}

func TestExtractMFATokenDuration2(t *testing.T) {
	data, err := os.ReadFile("testdata/assertion_invalid_date.xml")
	assert.Nil(t, err)

	_, err = ExtractMFATokenExpiryTime(data)
	t.Log(err)
	assert.NotNil(t, err)
}
