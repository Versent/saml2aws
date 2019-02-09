package f5apm

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/provider"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("provider", "f5apm")

//Client client for F5 APM
type Client struct {
	client *provider.HTTPClient
}

// New create new F5 APM client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)
	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "Error building HTTP client")
	}
	return &Client{client: client}, nil
}

// Authenticate logs into F5 APM and returns a SAML response
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	authSubmitURL, authForm, err := ac.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "Error getting login form IDP")
	}
	/*
		data, err := ac.postLoginForm(authSubmitURL, authForm)
		if err != null {
			return "", errors.Wrap(err, "Error submitting login form")
		}
	*/
	if authSubmitURL == "" {
		return "", fmt.Errorf("Error submitting login form")
	}

	logger.Debug(authForm)
	return "", fmt.Errorf("Not implemented yet")
}

func (ac *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {
	res, err := ac.client.Get(loginDetails.URL)
	if err != nil {
		return "", nil, errors.Wrap(err, "Error retrieving form")
	}
	logger.Debug(res)
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "Failed to build document from response")
	}
	authForm := url.Values{}
	fmt.Printf("loginDetails: %#v\n", loginDetails)
	fmt.Printf("doc: %#v\n", doc)
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		//fmt.Printf("Name: %s\nOk: %v\n", name, ok)
		if !ok {
			return
		}
		lname := strings.ToLower(name)
		if strings.Contains(lname, "username") {
			fmt.Printf("Username: %s\n", name)
			authForm.Add(name, loginDetails.Username)
		} else if strings.Contains(lname, "password") {
			fmt.Printf("Password: %s\n", name)
			authForm.Add(name, loginDetails.Password)
		} else {
			val, ok := s.Attr("value")
			if !ok {
				return
			}
			fmt.Printf("Value: %s\n", val)
			authForm.Add(name, val)
		}
	})
	fmt.Printf("authForm: %#v\n", authForm)
	authSubmitURL := ""
	if err != nil {
		return "", nil, errors.Wrap(err, "Unable to local IDP authentication form submit URL")
	}
	return authSubmitURL, authForm, nil
}
