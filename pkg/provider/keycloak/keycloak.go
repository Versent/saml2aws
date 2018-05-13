package keycloak

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"

	"fmt"
)

var logger = logrus.WithField("provider", "keycloak")

// Client wrapper around KeyCloak.
type Client struct {
	client *provider.HTTPClient
}

// New create a new KeyCloakClient
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into KeyCloak and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	authSubmitURL, authForm, err := kc.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form from idp")
	}

	data, err := kc.postLoginForm(authSubmitURL, authForm)
	if err != nil {
		return "", fmt.Errorf("error submitting login form")
	}
	if authSubmitURL == "" {
		return "", fmt.Errorf("error submitting login form")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	if containsTotpForm(doc) {
		totpSubmitURL, err := extractSubmitURL(doc)
		if err != nil {
			return "", errors.Wrap(err, "unable to locate IDP totp form submit URL")
		}

		doc, err = kc.postTotpForm(totpSubmitURL, doc)
		if err != nil {
			return "", errors.Wrap(err, "error posting totp form")
		}
	}

	var samlAssertion string

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			log.Fatalf("unable to locate IDP authentication form submit URL")
		}
		if name == "SAMLResponse" {
			val, ok := s.Attr("value")
			if !ok {
				log.Fatalf("unable to locate saml assertion value")
			}
			samlAssertion = val
		}
	})

	return samlAssertion, nil
}

func (kc *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	res, err := kc.client.Get(loginDetails.URL)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build document from response")
	}

	authForm := url.Values{}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateKeyCloakFormData(authForm, s, loginDetails)
	})

	authSubmitURL, err := extractSubmitURL(doc)
	if err != nil {
		return "", nil, errors.Wrap(err, "unable to locate IDP authentication form submit URL")
	}

	return authSubmitURL, authForm, nil
}

func (kc *Client) postLoginForm(authSubmitURL string, authForm url.Values) ([]byte, error) {

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body")
	}

	return data, nil
}

func (kc *Client) postTotpForm(totpSubmitURL string, doc *goquery.Document) (*goquery.Document, error) {

	otpForm := url.Values{}

	var token = prompter.RequestSecurityCode("000000")

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateOTPFormData(otpForm, s, token)
	})

	req, err := http.NewRequest("POST", totpSubmitURL, strings.NewReader(otpForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving content")
	}

	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "error reading totp form response")
	}

	return doc, nil
}

func extractSubmitURL(doc *goquery.Document) (string, error) {

	var submitURL string

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		submitURL = action
	})

	if submitURL == "" {
		return "", fmt.Errorf("unable to locate form submit URL")
	}

	return submitURL, nil
}

func containsTotpForm(doc *goquery.Document) bool {
	totpIndex := doc.Find("input#totp").Index()

	if totpIndex != -1 {
		return true
	}

	return false
}

func updateKeyCloakFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	// log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "username") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "password") {
		authForm.Add(name, user.Password)
	} else {
		// pass through any hidden fields
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		authForm.Add(name, val)
	}
}

func updateOTPFormData(otpForm url.Values, s *goquery.Selection, token string) {
	name, ok := s.Attr("name")
	//	log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "totp") {
		otpForm.Add(name, token)
	}

}
