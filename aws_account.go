package saml2aws

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

var awsURL = "https://signin.aws.amazon.com/saml"

// AWSAccount holds the AWS account name and roles
type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

// ParseAWSAccounts extract the aws accounts from the saml assertion
func ParseAWSAccounts(samlAssertion string) ([]*AWSAccount, error) {
	decSamlAssertion, _ := b64.StdEncoding.DecodeString(samlAssertion)
	if strings.Contains(string(decSamlAssertion), "signin.amazonaws.cn") {
		fmt.Println("trying to login AWS China")
		awsURL = "https://signin.amazonaws.cn/saml"
	}

	res, err := http.PostForm(awsURL, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving AWS login body")
	}

	return ExtractAWSAccounts(data)
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*AWSAccount, error) {
	accounts := []*AWSAccount{}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		account := new(AWSAccount)
		account.Name = s.Find("div.saml-account-name").Text()
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			role := new(AWSRole)
			role.Name = s.Text()
			role.RoleARN, _ = s.Attr("for")
			account.Roles = append(account.Roles, role)
		})
		accounts = append(accounts, account)
	})

	return accounts, nil
}

// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*AWSRole, awsAccounts []*AWSAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range awsAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*AWSRole, roleName string) (*AWSRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}
