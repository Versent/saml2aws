package pingfed

import (
	"fmt"
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

var logger = logrus.WithField("provider", "pingfed")

// Client wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
	//authSubmitURL string
	//samlAssertion string
	//mfaRequired   bool
}

// New create a new PingFed client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	//disable default behaviour to follow redirects as we use this to detect mfa
	client.DisableFollowRedirect()

	return &Client{
		client:     client,
		idpAccount: idpAccount,
		//mfaRequired: false,
	}, nil
}

// Authenticate Authenticate to PingFed and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	authSubmitURL, authForm, err := ac.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("authSubmitURL", authSubmitURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("authSubmitURL", authSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	var mfaRequired bool

	//check for redirect, this indicates PingOne MFA being used
	if res.StatusCode == 302 {
		mfaRequired = true
	}

	logger.WithField("mfaRequired", mfaRequired).Debug("POST")

	//process mfa
	if mfaRequired {

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

		logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("POST")

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving mfa response")
		}

		logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST")

		doc, err := goquery.NewDocumentFromResponse(res)
		if err != nil {
			return "", errors.Wrap(err, "failed to build document from response")
		}

		//extract form action and csrf token
		form, actionURL, err = extractMfaFormData(doc)
		if err != nil {
			return "", errors.Wrap(err, "error extracting authentication form")
		}

		logger.WithField("actionURL", actionURL).Debug("POST")

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
			token := prompter.StringRequired("Enter passcode")

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
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	var ok bool

	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", errors.Wrap(err, "unable to locate saml response")
	}

	logger.WithField("samlAssertion", samlAssertion).Debug("SAMLResponse")

	return samlAssertion, nil
}

func (ac *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	authForm := url.Values{}

	pingFedURL := fmt.Sprintf("%s/idp/startSSO.ping?PartnerSpId=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)

	logger.WithField("url", pingFedURL).Debug("GET")

	res, err := ac.client.Get(pingFedURL)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateLoginFormData(authForm, s, loginDetails)
	})

	authSubmitURL := ""

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return "", nil, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	return fmt.Sprintf("%s%s", loginDetails.URL, authSubmitURL), authForm, nil
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

	// extract form data to passthrough
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

func extractMfaFormData(doc *goquery.Document) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string
	//get action url
	doc.Find("#form1").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// extract form data to passthrough
	doc.Find("#form1 > input").Each(func(i int, s *goquery.Selection) {
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
