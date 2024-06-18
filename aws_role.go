package saml2aws

import (
	"fmt"
	"regexp"
	"strings"
)

// AWSRole aws role attributes
type AWSRole struct {
	RoleARN      string
	PrincipalARN string
	Name         string
}

// ParseAWSRoles parses and splits the roles while also validating the contents
func ParseAWSRoles(roles []string) ([]*AWSRole, error) {
	awsRoles := make([]*AWSRole, len(roles))

	for i, role := range roles {
		r, _ := regexp.Compile("arn:([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):(([^:/\n]*)[:/])?([^:,\n]*)")
		tokens := r.FindAllString(role, -1)
		if len(tokens) == 1 {
			continue
		}
		awsRole, err := parseRole(role)
		if err != nil {
			return nil, err
		}

		awsRoles[i] = awsRole
	}

	return awsRoles, nil
}

func parseRole(role string) (*AWSRole, error) {
	r, _ := regexp.Compile("arn:([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):(([^:/\n]*)[:/])?([^:,\n]*)")
	tokens := r.FindAllString(role, -1)

	if len(tokens) != 2 {
		return nil, fmt.Errorf("Invalid role string only %d tokens", len(tokens))
	}

	fmt.Println(tokens)

	awsRole := &AWSRole{}

	for _, token := range tokens {
		if strings.Contains(token, ":saml-provider") {
			awsRole.PrincipalARN = strings.TrimSpace(token)
		}
		if strings.Contains(token, ":role") {
			awsRole.RoleARN = strings.TrimSpace(token)
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
