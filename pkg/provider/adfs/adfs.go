package adfs

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "adfs")

// Client wrapper around ADFS enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new ADFS client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate to ADFS and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var authSubmitURL string
	var samlAssertion string

	awsURN := url.QueryEscape(ac.idpAccount.AmazonWebservicesURN)

	adfsURL := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=%s", loginDetails.URL, awsURN)

	res, err := ac.client.Get(adfsURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving form")
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

	res, err = ac.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form results")
	}

	switch ac.idpAccount.MFA {
	case "Azure":
		res, err = ac.azureMFA(authSubmitURL, loginDetails.MFAToken, res)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
		}
	case "VIP":
		res, err = ac.vipMFA(authSubmitURL, loginDetails.MFAToken, res)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
		}
	}

	// just parse the response whether res is from the login form or MFA form
	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login response body")
	}

	errorText := doc.Find("#errorText").Text()

	if errorText != "" {
		return samlAssertion, errors.New(errorText)
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

// azureMFA handler
func (ac *Client) azureMFA(authSubmitURL string, mfaToken string, res *http.Response) (*http.Response, error) {

	// Copy the body byte stream for re-use later
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading response body")
	}

	// Reset response body to avoid error if response is returned later
	res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving MFA form response body")
	}

	errorMessage := doc.Find("#errorMessage").Text()

	if strings.Contains(errorMessage, "authentication method is not available") {
		return nil, errors.New("You must setup MFA via https://aka.ms/mfasetup")
	} else if errorMessage != "" {
		return nil, errors.New(errorMessage)
	}

	azureIndex := doc.Find("input#authMethod[value=AzureMfaAuthentication]").Index()

	if azureIndex == -1 {
		// Reset response body to avoid error if response is returned later
		res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		return res, nil // if we didn't find the MFA flag then just continue
	}

	logger.Debug("Found Azure MFA form")

	mfaForm := url.Values{}

	mfaFormURL, _ := doc.Find("form#options").Attr("action")

	instructions := doc.Find("#instructions").Text()

	log.Printf(instructions)

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateAzureFormData(mfaForm, s)
	})

	for start := time.Now(); time.Since(start) < 120*time.Second; {
		if strings.Contains(instructions, "verification") {
			logger.Debug("Azure MFA code required")

			mfaCode := prompter.StringRequired("Enter MFA code")
			mfaForm.Set("VerificationCode", mfaCode)

			logger.Debugf("Azure MFA form: %v", mfaForm)
			req, err := http.NewRequest("POST", mfaFormURL, strings.NewReader(mfaForm.Encode()))
			if err != nil {
				return nil, errors.Wrap(err, "error building MFA verification form request")
			}

			res, err = ac.client.Do(req)
			if err != nil {
				return nil, errors.Wrap(err, "error retrieving MFA verification form")
			}

			doc, err = goquery.NewDocumentFromResponse(res)
			if err != nil {
				return nil, errors.Wrap(err, "error retrieving MFA verification form body")
			}

			doc.Find("input").Each(func(i int, s *goquery.Selection) {
				updateAzureFormData(mfaForm, s)
			})
		}

		logger.Debugf("Azure MFA form: %v", mfaForm)
		req, err := http.NewRequest("POST", mfaFormURL, strings.NewReader(mfaForm.Encode()))
		if err != nil {
			return nil, errors.Wrap(err, "error building MFA request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		time.Sleep(5 * time.Second)

		res, err = ac.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving content")
		}

		// Copy the body byte stream for re-use later
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error reading response body")
		}

		// Reset response body to avoid error when reading for SAML response
		res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		doc, err = goquery.NewDocumentFromResponse(res)

		samlResponse := doc.Find("input[name=SAMLResponse]").Length()

		if samlResponse == 1 {
			// Reset response body to avoid error when reading for SAML response
			res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			return res, nil
		}
	}

	return nil, errors.New("Unable to complete Azure MFA verification")
}

// vipMFA when supplied with the the form response document attempt to extract the VIP mfa related field
// then use that to trigger a submit of the MFA security token
func (ac *Client) vipMFA(authSubmitURL string, mfaToken string, res *http.Response) (*http.Response, error) {

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving saml response body")
	}

	otpForm := url.Values{}

	vipIndex := doc.Find("input#authMethod[value=VIPAuthenticationProviderWindowsAccountName]").Index()

	if vipIndex == -1 {
		return res, nil // if we didn't find the MFA flag then just continue
	}

	if mfaToken == "" {
		mfaToken = prompter.RequestSecurityCode("000000")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateOTPFormData(otpForm, s, mfaToken)
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

func updateAzureFormData(authForm url.Values, s *goquery.Selection) {
	name, ok := s.Attr("name")
	if !ok {
		return
	}

	val, ok := s.Attr("value")
	if !ok {
		return
	}

	switch name {
	case
		"AuthMethod",
		"Context":
		authForm.Set(name, val)
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
