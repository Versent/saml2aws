package saml2aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRoles(t *testing.T) {

	roles := []string{
		"arn:aws:iam::456456456456:saml-provider/example-idp,arn:aws:iam::456456456456:role/admin",
		"arn:aws:iam::456456456456:role/admin,arn:aws:iam::456456456456:saml-provider/example-idp",
	}

	awsRoles, err := ParseAWSRoles(roles)

	assert.Nil(t, err)
	assert.Len(t, awsRoles, 2)

	for _, awsRole := range awsRoles {
		assert.Equal(t, "arn:aws:iam::456456456456:saml-provider/example-idp", awsRole.PrincipalARN)
		assert.Equal(t, "arn:aws:iam::456456456456:role/admin", awsRole.RoleARN)
	}

	roles = []string{""}
	awsRoles, err = ParseAWSRoles(roles)

	assert.NotNil(t, err)
	assert.Nil(t, awsRoles)

}
