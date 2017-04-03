package saml2aws

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	prompt "github.com/segmentio/go-prompt"

	"encoding/json"

	"golang.org/x/net/publicsuffix"
)

// OktaClient is a wrapper representing a Okta SAML client
type OktaClient struct {
	client *http.Client
}

// MfaRequest represents an mfa okta request
type MfaRequest struct {
	ActivationCode        string `json:"activationCode"`
	RememberDeviceAllowed bool   `json:"rememberDeviceAllowed"`
	RememberDevice        bool   `json:"rememberDevice"`
	DeviceID              string `json:"deviceId"`
	DuoFactorType         string `json:"duoFactorType"`
	IsNewAttempt          bool   `json:"isNewAttempt"`
}

// MfaResponse represents an mfa okta response
type MfaResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// NewOktaClient creates a new Okta client
func NewOktaClient(skipVerify bool) (*OktaClient, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: tr, Jar: jar}

	return &OktaClient{
		client: client,
	}, nil
}

// Authenticate logs into Okta and returns a SAML response
func (oc *OktaClient) Authenticate(loginDetails *LoginDetails) (string, error) {
	var authSubmitURL string
	var samlAssertion string

	authForm := url.Values{}
	oktaEntryURL := fmt.Sprintf("https://%s", loginDetails.Hostname)
	url, err := url.Parse(oktaEntryURL)
	oktaOrgHost := url.Host

	res, err := oc.client.Get(oktaEntryURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateOktaLoginForm(authForm, s, loginDetails)
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

	//use the host value from the previous response and add the extracted action url
	authSubmitURL = fmt.Sprintf("https://%s/%s", oktaOrgHost, authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	//client will follow redirects by default
	res, err = oc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving auth response")
	}

	//use the final url to check to see if MFA is required
	if strings.Contains(res.Request.URL.String(), "/login/second-factor-challenge") {
		//MFA is required

		//parse response
		doc, err := goquery.NewDocumentFromResponse(res)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error parsing response")
		}

		//check if its DUO integrated
		if isDuoMfa(doc) {
			//prompt for mfa type
			//only supporting push or passcode for now
			var token string

			var mfaOptions = []string{
				"passcode",
				"push",
			}

			mfaOption := prompt.Choose("Select a DUO MFA Option", mfaOptions)

			if mfaOptions[mfaOption] == "passcode" {
				//get users DUO MFA Token
				token = prompt.StringRequired("Enter passcode")
			}

			//construct mfa request use deviceID and xsrfToken from previous response

			deviceID := extractDeviceID(doc)

			xsrfToken := doc.Find("#_xsrfToken").Text()

			mfaSubmitURL := fmt.Sprintf("https://%s/user/settings/factors/duo/auth", oktaOrgHost)

			mfaReq := MfaRequest{ActivationCode: token, RememberDeviceAllowed: true, RememberDevice: false, DeviceID: deviceID, DuoFactorType: mfaOptions[mfaOption], IsNewAttempt: true}

			mfaRes, err := sendMfaRequest(mfaSubmitURL, xsrfToken, mfaReq, oc)
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error parsing response")
			}

			if mfaRes.Status == "WAITING" {
				println(mfaRes.Message)
				//handle push
				for {
					time.Sleep(3 * time.Second)

					mfaReq := MfaRequest{ActivationCode: token, RememberDeviceAllowed: true, RememberDevice: false, DeviceID: deviceID, DuoFactorType: mfaOptions[mfaOption], IsNewAttempt: false}

					mfaRes, err := sendMfaRequest(mfaSubmitURL, xsrfToken, mfaReq, oc)
					if err != nil {
						return samlAssertion, errors.Wrap(err, "error parsing response")
					}

					if mfaRes.Status == "SUCCESS" || mfaRes.Status == "FAILED" {
						break
					}
				}
			}

			//or failed
			if mfaRes.Status == "FAILED" {
				return samlAssertion, errors.Wrap(err, mfaRes.Message)
			}

			//go back to original entry url as session is now mfa
			res, err = oc.client.Get(oktaEntryURL + "?fromLogin=true")
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retieving form")
			}

		} else {
			return samlAssertion, errors.Wrap(err, "unsupported mfa handler")
		}
	}

	//try to extract SAMLResponse
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
	}

	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return samlAssertion, errors.Wrap(err, "unable to locate saml response")
	}

	return samlAssertion, nil
}

//check the html response looking for a specific h1 value
func isDuoMfa(doc *goquery.Document) bool {
	isDuo := false

	if doc.Find("h1").Contents().Text() == "Select a Duo Authentication type" {
		isDuo = true
	}

	return isDuo
}

func extractDeviceID(doc *goquery.Document) string {
	var deviceID string

	doc.Find("[id$=\"-challenge-section\"]").Each(func(i int, s *goquery.Selection) {
		deviceID, _ = s.Attr("data-value")
	})

	return deviceID
}

func sendMfaRequest(url string, xsrfToken string, mfaReq MfaRequest, oc *OktaClient) (MfaResponse, error) {

	var mfaRes MfaResponse
	mfaBody := new(bytes.Buffer)
	json.NewEncoder(mfaBody).Encode(mfaReq)

	req, err := http.NewRequest("POST", url, mfaBody)
	if err != nil {
		return mfaRes, errors.Wrap(err, "error building mfa request")
	}

	req.Header.Add("X-Okta-XsrfToken", xsrfToken)
	req.Header.Add("Content-Type", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return mfaRes, errors.Wrap(err, "error retrieving auth response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return mfaRes, errors.Wrap(err, "error reading response")
	}

	json.Unmarshal(body, &mfaRes)

	return mfaRes, nil
}

func updateOktaLoginForm(authForm url.Values, s *goquery.Selection, user *LoginDetails) {
	name, ok := s.Attr("name")
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
