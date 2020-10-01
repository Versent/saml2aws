package f5apm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"

	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/dump"
	"github.com/versent/saml2aws/v2/pkg/prompter"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/provider"

	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("provider", "f5apm")

//Client client for F5 APM
type Client struct {
	client   *provider.HTTPClient
	policyID string
}

// New create new F5 APM client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)
	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "Error building HTTP client")
	}
	return &Client{client: client, policyID: idpAccount.ResourceID}, nil
}

// Authenticate logs into F5 APM and returns a SAML response
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	logger.Debug("Get Login Form")
	logger.Debugf("Login URL: %s", loginDetails.URL)
	logger.Debugf("Login Username: %s", loginDetails.Username)
	authForm, err := ac.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "Error getting login form IDP")
	}

	// Post username/password
	logger.Debug("Post UP Login Form")
	debugAuthForm(authForm)

	upData, err := ac.postLoginForm(loginDetails, authForm)
	if err != nil {
		return "", errors.Wrap(err, "Error submitting login form")
	}

	upDoc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(upData))
	if err != nil {
		return "", errors.Wrap(err, "Error reading UP data")
	}
	mfaFound, mfaMethods := containsMFAForm(upDoc)

	// Prompt for MFA if needed
	if mfaFound {
		logger.Debug(mfaMethods)
		mfaAuthForm := url.Values{}
		var mfaToken string
		mfaMethod, err := prompter.ChooseWithDefault("MFA Method", mfaMethods[0], mfaMethods)
		if err != nil {
			return "", errors.Wrap(err, "Error selecting MFA method")
		}
		switch mfaMethod {
		case "token":
			mfaToken = prompter.RequestSecurityCode("000000")
		case "push":
			mfaToken = ""
		}
		// Post mfatoken
		mfaAuthForm.Add("mfatoken", mfaToken)
		mfaAuthForm.Add("mfamethod", mfaMethod)
		mfaAuthForm.Add("mfa_retry", "")
		logger.Debug("Post Token Form")
		debugAuthForm(mfaAuthForm)
		_, err = ac.postLoginForm(loginDetails, mfaAuthForm)
		if err != nil {
			return "", errors.Wrap(err, "Error submitting MFA login form")
		}
	}

	// Post to saml endpoint
	logger.Debug("Get SAML Form")
	samlAssertion, err := ac.getSAMLAssertion(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "Error getting saml assertion")
	}
	decodedAssertion, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return "", errors.Wrap(err, "Error decoding saml assertion")
	}
	if dump.ContentEnable() {
		logger.Debugf("SAMLAssertion: %s", string(decodedAssertion))

	}
	return samlAssertion, nil
}

func (ac *Client) getSAMLAssertion(loginDetails *creds.LoginDetails) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/saml/idp/res", loginDetails.URL), nil)

	if err != nil {
		return "", errors.Wrap(err, "Error building SAML assertion request")
	}
	debugHTTPRequest(ac, req)
	// Don't urlencode query string - APM bug
	req.URL.RawQuery = fmt.Sprintf("id=%s", ac.policyID)
	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Error retrieving SAML assertion request")
	}
	debugHTTPResponse(ac, res)
	samlData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "Error reading SAML assertion body")
	}
	var samlAssertion string
	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(samlData))
	if err != nil {
		return "", errors.Wrap(err, "Error reading SAML data")
	}
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			logger.Fatalf("Unable to locate IDP authentication")
		}
		if name == "SAMLResponse" {
			val, ok := s.Attr("value")
			if !ok {
				logger.Fatalf("Unable to locate SAML assertion value")
			}
			samlAssertion = val
		}
	})
	return samlAssertion, nil
}

func (ac *Client) getLoginForm(loginDetails *creds.LoginDetails) (url.Values, error) {
	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error building get loging form request")
	}
	debugHTTPRequest(ac, req)
	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving login form")
	}
	debugHTTPResponse(ac, res)

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to build document from response")
	}
	authForm := url.Values{}
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		lname := strings.ToLower(name)
		if strings.Contains(lname, "username") {
			authForm.Add(name, loginDetails.Username)
		} else if strings.Contains(lname, "password") {
			authForm.Add(name, loginDetails.Password)
		} else {
			val, ok := s.Attr("value")
			if !ok {
				return
			}
			authForm.Add(name, val)
		}
	})
	return authForm, nil
}

func (ac *Client) postLoginForm(loginDetails *creds.LoginDetails, authForm url.Values) ([]byte, error) {
	logger.Debug("Auth Post")

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/my.policy", loginDetails.URL), strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "Error building authentication request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.00) Gecko/20100101 Firefox/65.0")
	req.Header.Set("Accept", "*/*")

	req.Header.Add("Referer", fmt.Sprintf("%s/my.policy", loginDetails.URL))
	if authForm.Get("mfamethod") != "" {
		req.AddCookie(&http.Cookie{Name: "f5cid00", Value: "token"})
	}
	debugHTTPRequest(ac, req)
	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving login form")
	}
	debugHTTPResponse(ac, res)

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading response body")
	}
	return data, nil
}

func debugAuthForm(vals url.Values) {
	for key, values := range vals {
		if strings.ToLower(key) == "password" {
			values = []string{"XXXXXXXXX"}
		}
		logger.Debugf("%-20s %-18s: %-40s", "Auth Form:", key, strings.Join(values, ", "))
	}
}

func debugHTTPRequest(ac *Client, req *http.Request) {
	logger.Debug(dump.RequestString(req))
	logger.Debug(req.URL)
	for name, values := range req.Header {
		logger.Debugf("%-20s %-18s: %-40s", fmt.Sprintf("%s Request Header:", req.Method), name, strings.Join(values, ", "))
	}
	for _, reqCookie := range ac.client.Jar.Cookies(req.URL) {
		logger.Debugf("%-20s %-18s: %-40s %s", fmt.Sprintf("%s Request Cookie:", req.Method), reqCookie.Name, reqCookie.Value, reqCookie.Domain)
	}

}
func debugHTTPResponse(ac *Client, res *http.Response) {
	logger.Debug(dump.ResponseString(res))
	logger.Debug(res.Request.URL)
	for name, values := range res.Header {
		logger.Debugf("%-20s %-18s: %-40s", fmt.Sprintf("%s Response Header:", res.Request.Method), name, strings.Join(values, ", "))
	}
	for _, resCookie := range ac.client.Jar.Cookies(res.Request.URL) {
		logger.Debugf("%-20s %-18s: %-40s %s", fmt.Sprintf("%s Response Cookie:", res.Request.Method), resCookie.Name, resCookie.Value, resCookie.Domain)
	}
}

func containsMFAForm(doc *goquery.Document) (bool, []string) {
	containsMFA := false
	var mfaMethods []string
	// Look for a form input ID named "mfa_retry"
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		id, _ := s.Attr("id")
		if strings.Contains(id, "mfa_retry") {
			containsMFA = true
		}
	})
	doc.Find("select").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		if strings.Contains(name, "mfamethod") {
			s.Find("option").Each(func(i int, opt *goquery.Selection) {
				option, _ := opt.Attr("value")
				logger.Debugf("MFA options: %s", option)
				mfaMethods = append(mfaMethods, option)
			})
		}
	})
	if len(mfaMethods) == 0 {
		return false, nil
	}
	logger.Debugf("MFA Form: '%#v'", containsMFA)
	logger.Debugf("MFA Methods: '%#v'", mfaMethods)
	return containsMFA, mfaMethods
}
