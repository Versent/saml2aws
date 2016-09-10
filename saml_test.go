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
