package gossamer3

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAWSAccounts(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/saml.html")
	assert.Nil(t, err)

	accounts, err := ExtractAWSAccounts(data)
	assert.Nil(t, err)
	assert.Len(t, accounts, 2)

	account := accounts[0]
	assert.Equal(t, account.Name, "Account: account-alias (000000000001)")

	assert.Len(t, account.Roles, 2)
	role := account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Development")
	assert.Equal(t, role.Name, "Development")
	role = account.Roles[1]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Production")
	assert.Equal(t, role.Name, "Production")

	account = accounts[1]
	assert.Equal(t, account.Name, "Account: 000000000002")

	assert.Len(t, account.Roles, 1)
	role = account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000002:role/Production")
	assert.Equal(t, role.Name, "Production")
}

func TestAssignPrincipals(t *testing.T) {
	awsRoles := []*AWSRole{
		{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
	}

	awsAccounts := []*AWSAccount{
		{
			Roles: []*AWSRole{
				{
					RoleARN: "arn:aws:iam::000000000001:role/Development",
				},
			},
		},
	}

	AssignPrincipals(awsRoles, awsAccounts)

	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/test-idp", awsAccounts[0].Roles[0].PrincipalARN)
}

func TestLocateRole(t *testing.T) {
	awsRoles := []*AWSRole{
		{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
		{
			PrincipalARN: "arn:aws:iam::000000000002:saml-provider/test-idp",
			RoleARN:      "arn:aws:iam::000000000002:role/Development",
		},
	}

	role, err := LocateRole(awsRoles, "arn:aws:iam::000000000001:role/Development")

	assert.Empty(t, err)

	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", role.RoleARN)
}
