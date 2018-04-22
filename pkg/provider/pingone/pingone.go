package pingone

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

var logger = logrus.WithField("provider", "pingone")

// Client wrapper around PingOne + PingID enabling authentication and retrieval of assertions
type Client struct {
	client        *provider.HTTPClient
	idpAccount    *cfg.IDPAccount
	lastAccessUrl *url.URL
}

// New create a new PingOne client
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

func (ac *Client) EnableFollowRedirect() {
	ac.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		ac.lastAccessUrl = req.URL
		return nil
	}
}

// Authenticate Authenticate to PingOne and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var prompt = prompter.NewCli()

	// Access to PingOne
	authSubmitURL, authForm, err := ac.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	// Access to PingFederate
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

	// parse form for action(url), SAMLREquest, RelayState
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	postUrl, formData, err := parseSAMLResponseForm(doc)
	if err != nil {
		return "", errors.Wrap(err, "error parse SAMLResponse form")
	}

	// Redirect from PingFederate to PingOne
	ac.client.DisableFollowRedirect()

	req, err = http.NewRequest("POST", postUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request to PingOne")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("postUrl", postUrl).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err = ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("postUrl", postUrl).WithField("res", dump.ResponseString(res)).Debug("POST")

	// parse form for action(url), ppm_request, etc
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}
	postUrl, formData, err = parsePpmRequestForm(doc)
	if err != nil {
		return "", errors.Wrap(err, "error parse ppm_request form")
	}

	// post to /pingid/ppm/auth
	res, err = ac.client.PostForm(postUrl, formData)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("postUrl", postUrl).WithField("res", dump.ResponseString(res)).Debug("/pingid/ppm/auth")

	//extract form action and jwt token
	form, actionURL, err := extractFormData(res)
	if err != nil {
		return "", errors.Wrap(err, "error extracting mfa form data")
	}

	logger.WithField("actionURL", actionURL).Debug("POST")

	//request mfa auth via PingId (device swipe) /pingid/ppm/auth/poll
	req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building mfa authentication request")
	}

	logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("/pingid/ppm/auth/poll")

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving mfa response")
	}

	logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST /pingid/ppm/auth/poll")

	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	//extract form action and csrf token
	form, actionURL, err = extractMfaFormData(doc)
	if err != nil {
		return "", errors.Wrap(err, "error extracting authentication form")
	}

	logger.WithField("actionURL", actionURL).WithField("form", form).Debug("extract mfa form")

	//contine mfa auth with csrf token
	req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("extract mfa form")

	// accept mfa
	res, err = ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error polling mfa device")
	}

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

	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", errors.Wrap(err, "unable to locate saml response")
	}

	logger.WithField("samlAssertion", samlAssertion).Debug("SAMLResponse")

	return samlAssertion, nil
}

func (ac *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	// request to PingOne
	res, err := ac.client.Get(loginDetails.URL)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving AuthnRequest form")
	}

	logger.WithField("status", res.StatusCode).WithField("url", loginDetails.URL).WithField("res", dump.ResponseString(res)).Debug("GET")

	// parse form for action(url), SAMLRequest, RelayState
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "error parsing document")
	}

	postUrl, formData, err := parseSAMLRequestForm(doc)
	if err != nil {
		return "", nil, errors.Wrap(err, "error parse SAMLRequest form")
	}

	// AuthnRequest to PingFederate
	ac.EnableFollowRedirect()
	res, err = ac.client.PostForm(postUrl, formData)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("res", dump.ResponseString(res)).WithField("redirect_url", ac.lastAccessUrl).Debug("POST")

	// 401 Unauthorized -> refresh same page with cookie
	res, err = ac.client.Get(ac.lastAccessUrl.String())
	if err != nil {
		return "", nil, errors.Wrap(err, "error refresh same page")
	}

	logger.WithField("res", dump.ResponseString(res)).Debug("GET")

	// Get login form
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateLoginFormData(formData, s, loginDetails)
	})

	formAction := ""

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		formAction = action
	})

	if formAction == "" {
		return "", nil, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	authSubmitURL, err := url.Parse(formAction)
	if err != nil {
		return "", nil, fmt.Errorf("unable parse form action")
	}

	if !authSubmitURL.IsAbs() {
		authSubmitURL.Scheme = ac.lastAccessUrl.Scheme
		authSubmitURL.Host = ac.lastAccessUrl.Host
	}

	return authSubmitURL.String(), formData, nil
}

func parseSAMLRequestForm(doc *goquery.Document) (string, url.Values, error) {

	formSelection := doc.Find("form")
	postUrl, exists := formSelection.Attr("action")
	if !exists {
		return "", nil, fmt.Errorf("error parsing form")
	}

	formData := url.Values{}
	samlRequest, exists := formSelection.Find("input[name=\"SAMLRequest\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error SAMLRequest not found")
	}
	formData.Add("SAMLRequest", samlRequest)

	relayState, exists := formSelection.Find("input[name=\"RelayState\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error RelayState not found")
	}
	formData.Add("RelayState", relayState)

	logger.WithField("url", postUrl).WithField("SAMLRequest", samlRequest).WithField("RelayState", relayState).Debug("SAMLRequest")

	return postUrl, formData, nil
}

func parseSAMLResponseForm(doc *goquery.Document) (string, url.Values, error) {

	formSelection := doc.Find("form")
	postUrl, exists := formSelection.Attr("action")
	if !exists {
		return "", nil, fmt.Errorf("error parsing form")
	}

	formData := url.Values{}
	samlRequest, exists := formSelection.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error SAMLResponse not found")
	}
	formData.Add("SAMLResponse", samlRequest)

	relayState, exists := formSelection.Find("input[name=\"RelayState\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error RelayState not found")
	}
	formData.Add("RelayState", relayState)

	logger.WithField("url", postUrl).WithField("SAMLResponse", samlRequest).WithField("RelayState", relayState).Debug("SAMLResponse")

	return postUrl, formData, nil
}

func parsePpmRequestForm(doc *goquery.Document) (string, url.Values, error) {

	formSelection := doc.Find("form")
	postUrl, exists := formSelection.Attr("action")
	if !exists {
		return "", nil, fmt.Errorf("error parsing form")
	}

	formData := url.Values{}
	ppmRequest, exists := formSelection.Find("input[name=\"ppm_request\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error ppm_request not found")
	}
	formData.Add("ppm_request", ppmRequest)

	iss, exists := formSelection.Find("input[name=\"iss\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error iss not found")
	}
	formData.Add("iss", iss)

	idpAccountId, exists := formSelection.Find("input[name=\"idp_account_id\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error idp_account_id not found")
	}
	formData.Add("idp_account_id", idpAccountId)

	userAgentId, exists := formSelection.Find("input[name=\"userAgentId\"]").Attr("value")
	if !exists {
		return "", nil, fmt.Errorf("error userAgentId not found")
	}
	formData.Add("userAgentId", userAgentId)

	logger.WithField("postUrl", postUrl).WithField("ppm_request", ppmRequest).WithField("iss", iss).WithField("idp_account_id", idpAccountId).WithField("userAgentId", userAgentId).Debug("ppm_request")

	return postUrl, formData, nil
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
	doc.Find("form[method=\"POST\"]").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// extract form data to passthrough
	doc.Find("form[method=\"POST\"] > input").Each(func(i int, s *goquery.Selection) {
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
