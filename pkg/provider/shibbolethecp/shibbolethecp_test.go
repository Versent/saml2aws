package shibbolethecp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"os"

	"github.com/beevik/etree"
)

func TestAuthnRequest(t *testing.T) {
	input := "foo"

	result, err := authnRequest(input)
	assert.NoError(t, err)

	doc := etree.NewDocument()
	_, err = doc.ReadFrom(result)
	assert.NoError(t, err)

	root := doc.Root()

	// find Issuer element
	element := root.FindElement("//saml2:Issuer")
	assert.NotNil(t, element)

	// check Issuer value
	value := element.Text()
	assert.Equal(t, input, strings.TrimSpace(value))
}

func TestExtractAssertion(t *testing.T) {
	data, err := os.Open("testdata/ecp_soap_response_success.xml")
	assert.Nil(t, err)

	assertion, err := extractAssertion(data)
	assert.Nil(t, err)
	assert.NotEmpty(t, assertion)
}
