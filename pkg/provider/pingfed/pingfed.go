package pingfed

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "pingfed")

// Client wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new PingFed client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// assign a response validator to ensure all responses are either success or a redirect
	// this is to avoid have explicit checks for every single response
	client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	//disable default behavior to follow redirects as we use this to detect mfa
	client.DisableFollowRedirect()

	return &Client{
		client:     client,
		idpAccount: idpAccount,
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

	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	var mfaRequired bool

	//check for redirect, this indicates PingOne MFA being used
	if res.StatusCode == 302 {
		mfaRequired = true
	}

	//process mfa
	if mfaRequired {

		mfaURL, err := res.Location()
		if err != nil {
			return "", errors.Wrap(err, "error building mfa url")
		}

		//follow redirect
		res, err = ac.client.Get(mfaURL.String())
		if err != nil {
			return "", errors.Wrap(err, "error retrieving form")
		}

		//extract form action and jwt token
		form, actionURL, err := extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting mfa form data")
		}

		//request mfa auth via PingId (device swipe)
		req, err := http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building mfa authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving mfa response")
		}

		doc, err := goquery.NewDocumentFromResponse(res)
		if err != nil {
			return "", errors.Wrap(err, "failed to build document from response")
		}

		//extract form action and csrf token
		form, actionURL, err = extractMfaFormData(doc, "#form1")
		if err != nil {
			return "", errors.Wrap(err, "error extracting authentication form")
		}

		//contine mfa auth with csrf token
		req, err = http.NewRequest("GET", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		otp := false

		//check if a push is happening
		if strings.Contains(actionURL, "/pingid/ppm/auth/status") {
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			for {
				time.Sleep(3 * time.Second)

				res, err = ac.client.Do(req)
				if err != nil {
					return "", errors.Wrap(err, "error polling mfa device")
				}

				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					return "", errors.Wrap(err, "error parsing body from mfa response")
				}

				resp := string(body)

				pingfedMFAStatusResponse := gjson.Get(resp, "status").String()

				//ASYNC_AUTH_WAIT indicates we keep going
				//OK indicates someone swiped
				//DEVICE_CLAIM_TIMEOUT indicates nobody swiped
				//otherwise loop forever?

				if pingfedMFAStatusResponse == "OK" {
					break
				}

				if pingfedMFAStatusResponse == "DEVICE_CLAIM_TIMEOUT" || pingfedMFAStatusResponse == "TIMEOUT" {
					otp = true
					break
				}

			}
		}

		//spelling mistake intentional, that's just how the form is
		form, actionURL, err = extractMfaFormData(doc, "#reponseView")
		if err != nil {
			return "", errors.Wrap(err, "error extracting post-mfa response location")
		}

		req, err = http.NewRequest("GET", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error calling success mfa response")
		}

		//Need to save this for later
		csrfForm := form

		if otp == true {

			doc, err = goquery.NewDocumentFromResponse(res)
			if err != nil {
				return "", errors.Wrap(err, "failed to build document from response")
			}

			form, actionURL, err = extractMfaFormData(doc, "#otp-form")
			if err != nil {
				return "", errors.Wrap(err, "error extracting otp form")
			}

		}

		// logger.WithField("actionURL", actionURL).Debug("POST-MFA")

		//if actionURL is OTP then prompt for token
		//user has disabled swipe
		if strings.Contains(actionURL, "/pingid/ppm/auth/otp") {
			token := prompter.StringRequired("Enter passcode")

			csrfForm.Add("otp", token)

			//submit otp
			req, err = http.NewRequest("POST", actionURL, strings.NewReader(csrfForm.Encode()))
			if err != nil {
				return "", errors.Wrap(err, "error building totp request")
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			res, err = ac.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error submitting totp")
			}

		}

		//extract form action and jwt token
		form, actionURL, err = extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting jwt form data")
		}

		//pass PingId auth back to pingfed
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error authenticating mfa")
		}

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

	logger.Debug("SAMLResponse received")

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

	authSubmitURL, err := extractAuthSubmitURL(loginDetails.URL, doc)
	if err != nil {
		return "", nil, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	return authSubmitURL, authForm, nil
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

func extractAuthSubmitURL(baseURL string, doc *goquery.Document) (authSubmitURL string, err error){
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		err = fmt.Errorf("unable to locate IDP authentication form submit URL")
		return
	}

	// account for relative action URI
	if url, urlErr := url.ParseRequestURI(authSubmitURL); urlErr == nil && !url.IsAbs() {
		authSubmitURL = fmt.Sprintf("%s%s", baseURL, authSubmitURL)
	}

	return
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

func extractMfaFormData(doc *goquery.Document, formID string) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string
	//get action url
	doc.Find(formID).Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// extract form data to passthrough
	searchString := formID + " > input"
	doc.Find(searchString).Each(func(i int, s *goquery.Selection) {
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
