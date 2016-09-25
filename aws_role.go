package saml2aws

import (
	"fmt"
	"strings"
)

// AWSRole aws role attributes
type AWSRole struct {
	RoleARN      string
	PrincipalARN string
}

// ParseAWSRoles parses and splits the roles while also validating the contents
func ParseAWSRoles(roles []string) ([]*AWSRole, error) {
	awsRoles := make([]*AWSRole, len(roles))

	for i, role := range roles {
		awsRole, err := parseRole(role)
		if err != nil {
			return nil, err
		}

		awsRoles[i] = awsRole
	}

	return awsRoles, nil
}

func parseRole(role string) (*AWSRole, error) {
	tokens := strings.Split(role, ",")

	if len(tokens) != 2 {
		return nil, fmt.Errorf("Invalid role string only %d tokens", len(tokens))
	}

	awsRole := &AWSRole{}

	for _, token := range tokens {
		if strings.Contains(token, ":saml-provider") {
			awsRole.PrincipalARN = token
		}
		if strings.Contains(token, ":role") {
			awsRole.RoleARN = token
		}
	}

	if awsRole.PrincipalARN == "" {
		return nil, fmt.Errorf("Unable to locate PrincipalARN in: %s", role)
	}

	if awsRole.RoleARN == "" {
		return nil, fmt.Errorf("Unable to locate RoleARN in: %s", role)
	}

	return awsRole, nil
}
