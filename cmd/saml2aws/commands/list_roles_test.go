package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	saml2aws "github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/pkg/flags"
)

// captureStdout replaces os.Stdout with a pipe for the duration of fn, then
// returns everything that was written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	old := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var sb strings.Builder
	_, err = io.Copy(&sb, r)
	require.NoError(t, err)
	return sb.String()
}

// samlAssertionFixture returns the base64-encoded contents of testdata/assertion.xml.
// The XML has Destination="https://signin.aws.amazon.com/saml".
func samlAssertionFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/assertion.xml")
	require.NoError(t, err)
	return b64.StdEncoding.EncodeToString(data)
}

// awsRolesForSAMLHTML returns a set of AWSRole values whose RoleARNs match
// the roles embedded in testdata/saml.html so that AssignPrincipals can link
// them to the accounts returned by the mocked AWS sign-in page.
func awsRolesForSAMLHTML() []*saml2aws.AWSRole {
	return []*saml2aws.AWSRole{
		{
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
		},
		{
			RoleARN:      "arn:aws:iam::000000000001:role/Production",
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
		},
		{
			RoleARN:      "arn:aws:iam::000000000002:role/Production",
			PrincipalARN: "arn:aws:iam::000000000002:saml-provider/test-idp",
		},
	}
}

// mockAWSSignIn registers a gock interceptor that responds to the POST that
// ParseAWSAccounts sends to https://signin.aws.amazon.com/saml with the
// contents of testdata/saml.html.
func mockAWSSignIn(t *testing.T) {
	t.Helper()
	samlHTML, err := os.ReadFile("../../../testdata/saml.html")
	require.NoError(t, err)

	gock.New("https://signin.aws.amazon.com").
		Post("/saml").
		Reply(200).
		BodyString(string(samlHTML))
}

func TestListRolesTextOutput(t *testing.T) {
	defer gock.Off()
	mockAWSSignIn(t)

	samlAssertion := samlAssertionFixture(t)
	awsRoles := awsRolesForSAMLHTML()
	loginFlags := &flags.LoginExecFlags{
		CommonFlags: &flags.CommonFlags{},
		JSON:        false,
	}

	output := captureStdout(t, func() {
		err := listRoles(awsRoles, samlAssertion, loginFlags)
		assert.NoError(t, err)
	})

	assert.Contains(t, output, "Account: account-alias (000000000001)")
	assert.Contains(t, output, "arn:aws:iam::000000000001:role/Development")
	assert.Contains(t, output, "arn:aws:iam::000000000001:role/Production")
	assert.Contains(t, output, "Account: 000000000002")
	assert.Contains(t, output, "arn:aws:iam::000000000002:role/Production")
}

// TestListRolesJSONOutput validates compact JSON output shape and values.
func TestListRolesJSONOutput(t *testing.T) {
	defer gock.Off()
	mockAWSSignIn(t)

	samlAssertion := samlAssertionFixture(t)
	awsRoles := awsRolesForSAMLHTML()
	loginFlags := &flags.LoginExecFlags{
		CommonFlags: &flags.CommonFlags{},
		JSON:        true,
	}

	output := captureStdout(t, func() {
		err := listRoles(awsRoles, samlAssertion, loginFlags)
		assert.NoError(t, err)
	})

	// Verify the output is valid JSON and has the expected structure.
	var accounts []struct {
		Name          string `json:"Name"`
		AccountNumber string `json:"AccountNumber"`
		AccountAlias  string `json:"AccountAlias"`
		Roles         []struct {
			RoleARN      string `json:"RoleARN"`
			PrincipalARN string `json:"PrincipalARN"`
			Name         string `json:"Name"`
		} `json:"Roles"`
	}
	trimmed := strings.TrimSpace(output)
	require.NoError(t, json.Unmarshal([]byte(trimmed), &accounts))

	// Compact JSON must be a single line (no embedded newlines).
	assert.NotContains(t, trimmed, "\n")

	require.Len(t, accounts, 2)

	assert.Equal(t, "Account: account-alias (000000000001)", accounts[0].Name)
	assert.Equal(t, "000000000001", accounts[0].AccountNumber)
	assert.Equal(t, "account-alias", accounts[0].AccountAlias)
	require.Len(t, accounts[0].Roles, 2)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", accounts[0].Roles[0].RoleARN)
	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/test-idp", accounts[0].Roles[0].PrincipalARN)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Production", accounts[0].Roles[1].RoleARN)

	assert.Equal(t, "Account: 000000000002", accounts[1].Name)
	assert.Equal(t, "000000000002", accounts[1].AccountNumber)
	assert.Equal(t, "", accounts[1].AccountAlias)
	require.Len(t, accounts[1].Roles, 1)
	assert.Equal(t, "arn:aws:iam::000000000002:role/Production", accounts[1].Roles[0].RoleARN)
	assert.Equal(t, "arn:aws:iam::000000000002:saml-provider/test-idp", accounts[1].Roles[0].PrincipalARN)
}

// TestListRolesJSONPrettyOutput validates pretty-printed JSON output shape and values.
func TestListRolesJSONPrettyOutput(t *testing.T) {
	defer gock.Off()
	mockAWSSignIn(t)

	samlAssertion := samlAssertionFixture(t)
	awsRoles := awsRolesForSAMLHTML()
	loginFlags := &flags.LoginExecFlags{
		CommonFlags: &flags.CommonFlags{},
		JSONPretty:  true,
	}

	output := captureStdout(t, func() {
		err := listRoles(awsRoles, samlAssertion, loginFlags)
		assert.NoError(t, err)
	})

	// Verify the output is valid JSON and has the expected structure.
	var accounts []struct {
		Name          string `json:"Name"`
		AccountNumber string `json:"AccountNumber"`
		AccountAlias  string `json:"AccountAlias"`
		Roles         []struct {
			RoleARN      string `json:"RoleARN"`
			PrincipalARN string `json:"PrincipalARN"`
			Name         string `json:"Name"`
		} `json:"Roles"`
	}
	trimmed := strings.TrimSpace(output)
	require.NoError(t, json.Unmarshal([]byte(trimmed), &accounts))

	// Pretty-printed JSON must contain newlines and indentation.
	assert.Contains(t, trimmed, "\n")
	assert.Contains(t, trimmed, "  ")

	require.Len(t, accounts, 2)

	assert.Equal(t, "Account: account-alias (000000000001)", accounts[0].Name)
	assert.Equal(t, "000000000001", accounts[0].AccountNumber)
	assert.Equal(t, "account-alias", accounts[0].AccountAlias)
	require.Len(t, accounts[0].Roles, 2)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", accounts[0].Roles[0].RoleARN)
	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/test-idp", accounts[0].Roles[0].PrincipalARN)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Production", accounts[0].Roles[1].RoleARN)

	assert.Equal(t, "Account: 000000000002", accounts[1].Name)
	assert.Equal(t, "000000000002", accounts[1].AccountNumber)
	assert.Equal(t, "", accounts[1].AccountAlias)
	require.Len(t, accounts[1].Roles, 1)
	assert.Equal(t, "arn:aws:iam::000000000002:role/Production", accounts[1].Roles[0].RoleARN)
	assert.Equal(t, "arn:aws:iam::000000000002:saml-provider/test-idp", accounts[1].Roles[0].PrincipalARN)
}

// TestListRolesReturnsErrorWhenNoRoles validates that listRoles returns an error when no roles are provided.
func TestListRolesReturnsErrorWhenNoRoles(t *testing.T) {
	loginFlags := &flags.LoginExecFlags{
		CommonFlags: &flags.CommonFlags{},
	}

	err := listRoles([]*saml2aws.AWSRole{}, "", loginFlags)

	assert.ErrorContains(t, err, "no roles available")
}
