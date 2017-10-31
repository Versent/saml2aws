package pingfed

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	prompt "github.com/segmentio/go-prompt"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/dump"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "pingfed")

// Client wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type Client struct {
	client        *provider.HTTPClient
	authSubmitURL string
	samlAssertion string
	mfaRequired   bool
}

// New create a new PingFed client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	//disable default behaviour to follow redirects as we use this to detect mfa
	client.DisableFollowRedirect()

	return &Client{
		client:      client,
		mfaRequired: false,
	}, nil
}

// Authenticate Authenticate to PingFed and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	authForm := url.Values{}

	pingFedURL := fmt.Sprintf("https://%s/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices", loginDetails.Hostname)

	logger.WithField("url", pingFedURL).Debug("GET")

	res, err := ac.client.Get(pingFedURL)
	if err != nil {
		return "", errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateLoginFormData(authForm, s, loginDetails)
	})

	//spew.Dump(authForm)

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		ac.authSubmitURL = action
	})

	if ac.authSubmitURL == "" {
		return "", fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	ac.authSubmitURL = fmt.Sprintf("https://%s%s", loginDetails.Hostname, ac.authSubmitURL)

	//log.Printf("id authentication url: %s", authSubmitURL)

	req, err := http.NewRequest("POST", ac.authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("authSubmitURL", ac.authSubmitURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err = ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("authSubmitURL", ac.authSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	//check for redirect, this indicates PingOne MFA being used
	if res.StatusCode == 302 {
		ac.mfaRequired = true
	}

	logger.WithField("mfaRequired", ac.mfaRequired).Debug("POST")

	//process mfa
	if ac.mfaRequired {

		mfaURL, err := res.Location()
		if err != nil {
			return "", errors.Wrap(err, "error building mfa url")
		}
		//spew.Dump(mfaURL)
		logger.WithField("mfaURL", mfaURL).Debug("GET")

		//follow redirect
		res, err = ac.client.Get(mfaURL.String())
		if err != nil {
			return "", errors.Wrap(err, "error retrieving form")
		}

		logger.WithField("mfaURL", mfaURL).WithField("res", dump.ResponseString(res)).Debug("GET")

		//extract form action and jwt token
		form, actionURL, err := extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting mfa form data")
		}

		logger.WithField("actionURL", actionURL).Debug("POST")

		//request mfa auth via PingId (device swipe)
		req, err := http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building mfa authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retieving mfa response")
		}

		logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST")

		//extract form action and csrf token
		form, actionURL, err = extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting authentication form")
		}

		//contine mfa auth with csrf token
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error polling mfa device")
		}

		//extract form action and jwt token
		form, actionURL, err = extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting jwt form data")
		}

		logger.WithField("actionURL", actionURL).Debug("POST")

		//if actionURL is OTP then prompt for token
		//user has disabled swipe
		if strings.Contains(actionURL, "/pingid/ppm/auth/otp") {
			token := prompt.StringRequired("Enter passcode")

			//build request
			otpReq := url.Values{}
			otpReq.Add("otp", token)
			otpReq.Add("message", "")

			//submit otp
			req, err = http.NewRequest("POST", actionURL, strings.NewReader(otpReq.Encode()))
			if err != nil {
				return "", errors.Wrap(err, "error building authentication request")
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("POST")

			res, err = ac.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error polling mfa device")
			}

			logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST")

			//extract form action and jwt token
			form, actionURL, err = extractFormData(res)
			if err != nil {
				return "", errors.Wrap(err, "error extracting mfa form data")
			}

		}

		//pass PingId auth back to pingfed
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("POST")

		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error authenticating mfa")
		}

		logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST")
	}

	//try to extract SAMLResponse
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	var ok bool

	ac.samlAssertion, ok = doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", errors.Wrap(err, "unable to locate saml response")
	}

	logger.WithField("samlAssertion", ac.samlAssertion).Debug("SAMLResponse")

	return ac.samlAssertion, nil
}

func updateLoginFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	//	log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "pf.username") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "pf.pass") {
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

func extractFormData(res *http.Response) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return formData, actionURL, errors.Wrap(err, "failed to build document from response")
	}

	//get action url
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// exxtract form data to passthrough
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		formData.Add(name, val)
	})

	return formData, actionURL, nil
}
