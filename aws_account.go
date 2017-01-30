package saml2aws

import (
	"bytes"
	"io/ioutil"
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

	res, err := http.PostForm(awsURL, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retieving AWS login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retieving AWS login body")
	}

	return ExtractAWSAccounts(data)
}

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
