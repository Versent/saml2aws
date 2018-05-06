package jumpcloud

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

// Client is a wrapper representing a JumpCloud SAML client
type Client struct {
	client *provider.HTTPClient
}

// New creates a new JumpCloud client
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

// Authenticate logs into JumpCloud and returns a SAML response
func (jc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	//var prompt = prompter.NewCli()

	var authSubmitURL string
	var samlAssertion string
	mfaRequired := false

	authForm := url.Values{}
	jumpCloudURL := loginDetails.URL

	res, err := jc.client.Get(jumpCloudURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateJumpCloudForm(authForm, s, loginDetails)
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

	authSubmitURL = fmt.Sprintf("https://sso.jumpcloud.com/%s", authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Temporarily disable following redirects so we can detect MFA.
	jc.client.DisableFollowRedirect()
	res, err = jc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form")
	}

	if res.StatusCode == 302 {
		location, err := res.Location()
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving redirect location")
		}

		if location.EscapedPath() == "/login/user/mfa" {
			mfaRequired = true
		} else {
			// Just follow the redirect.
			res, err = jc.client.Get(location.String())
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retrieving SAML response")
			}
		}
	}

	jc.client.EnableFollowRedirect()

	if mfaRequired {
		token := prompter.StringRequired("MFA Token")
		authForm.Add("otp", token)

		req, err = http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building MFA authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error submitting MFA login form")
		}
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving body")
	}

	doc, err = goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
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

func updateJumpCloudForm(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	if !ok {
		return
	}

	lname := strings.ToLower(name)
	if strings.Contains(lname, "email") {
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
