package saml2aws

import (
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

func ParseAWSAccounts(samlAssertion string) ([]*AWSAccount, error) {
	awsURL := "https://signin.aws.amazon.com/saml"
	accounts := []*AWSAccount{}

	res, err := http.PostForm(awsURL, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retieving AWS login form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
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
