package adfs

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/dump"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "adfs")

// Client wrapper around ADFS enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
	prompter   prompter.Prompter
}

// New create a new ADFS client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
		prompter:   prompter.NewCli(),
	}, nil
}

// Authenticate authenticate to ADFS and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var authSubmitURL string
	var samlAssertion string

	adfsURL := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", loginDetails.URL)

	res, err := ac.client.Get(adfsURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	authForm := url.Values{}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateFormData(authForm, s, loginDetails)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	//log.Printf("id authentication url: %s", authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("authSubmitURL", authSubmitURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err = ac.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form results")
	}

	//log.Printf("res code = %v status = %s", res.StatusCode, res.Status)
	logger.WithField("authSubmitURL", authSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	switch ac.idpAccount.MFA {
	case "VIP":
		res, err = ac.vipMFA(authSubmitURL, res)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
		}
	}

	// just parse the response whether res is from the login form or MFA form
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login response body")
	}

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

// vipMFA when supplied with the the form response document attempt to extract the VIP mfa related field
// then use that to trigger a submit of the MFA security token
func (ac *Client) vipMFA(authSubmitURL string, res *http.Response) (*http.Response, error) {

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving saml response body")
	}

	otpForm := url.Values{}

	vipIndex := doc.Find("input#authMethod[value=VIPAuthenticationProviderWindowsAccountName]").Index()

	if vipIndex == -1 {
		return res, nil // if we didn't find the MFA flag then just continue
	}

	var token = ac.prompter.RequestSecurityCode("000000")

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateOTPFormData(otpForm, s, token)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return nil, fmt.Errorf("unable to locate IDP MFA form submit URL")
	}

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(otpForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving content")
	}

	return res, nil
}

func updateFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	//	log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "user") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "email") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "pass") {
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
	if strings.Contains(lname, "security_code") {
		otpForm.Add(name, token)
	} else {
		// pass through any hidden fields
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		otpForm.Add(name, val)
	}

}
