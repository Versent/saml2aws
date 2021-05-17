package adfs

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

// Client wrapper around ADFS enabling authentication and retrieval of assertions
type Client struct {
	provider.ValidateBase

	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

type AuthResponseType int

const (
	UNKNOWN AuthResponseType = iota
	SAML_RESPONSE
	MFA_PROMPT
	AZURE_MFA_WAIT
	AZURE_MFA_SERVER_WAIT
)

// New create a new ADFS client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
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
	var instructions string

	awsURN := url.QueryEscape(ac.idpAccount.AmazonWebservicesURN)

	adfsURL := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=%s", loginDetails.URL, awsURN)

	mfaToken := loginDetails.MFAToken

	doc, err := ac.get(adfsURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to get adfs page")
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

	doc, err = ac.submit(authSubmitURL, authForm)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to submit adfs auth form")
	}

	for {
		responseType, samlAssertion, err := checkResponse(doc)

		switch responseType {
		case SAML_RESPONSE:
			return samlAssertion, err
		case MFA_PROMPT:
			otpForm := url.Values{}
			if mfaToken == "" {
				mfaToken = prompter.RequestSecurityCode("000000")
			}

			doc.Find("input").Each(func(i int, s *goquery.Selection) {
				updateOTPFormData(otpForm, s, mfaToken)
			})
			doc, err = ac.submit(authSubmitURL, otpForm)
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
			}
			mfaToken = ""
		case AZURE_MFA_SERVER_WAIT:
			fallthrough
		case AZURE_MFA_WAIT:
			azureForm := url.Values{}
			doc.Find("input").Each(func(i int, s *goquery.Selection) {
				updatePassthroughFormData(azureForm, s)
			})
			sel := doc.Find("p#instructions")
			if sel.Index() != -1 {
				if instructions != sel.Text() {
					instructions = sel.Text()
					log.Println(instructions)
				}
			}
			time.Sleep(1 * time.Second)
			doc, err = ac.submit(authSubmitURL, azureForm)
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
			}
			if responseType == AZURE_MFA_SERVER_WAIT {
				sel := doc.Find("label#errorText")
				if sel.Index() != -1 {
					return samlAssertion, errors.New(sel.Text())
				}
			}
		case UNKNOWN:
			return samlAssertion, errors.New("unable to classify response from auth server")
		}
	}
}

func (ac *Client) get(url string) (*goquery.Document, error) {
	res, err := ac.client.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "error retieving form")

	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}
	return doc, nil
}

func (ac *Client) submit(url string, form url.Values) (*goquery.Document, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error submitting form")

	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}
	return doc, nil
}

func checkResponse(doc *goquery.Document) (AuthResponseType, string, error) {
	samlAssertion := ""
	responseType := UNKNOWN

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
			responseType = SAML_RESPONSE
		}
		if name == "AuthMethod" {
			val, _ := s.Attr("value")
			switch val {
			case "VIPAuthenticationProviderWindowsAccountName", "VIPAuthenticationProviderUPN", "Defender AD FS Adapter":
				responseType = MFA_PROMPT
			case "AzureMfaAuthentication":
				responseType = AZURE_MFA_WAIT
			case "AzureMfaServerAuthentication":
				responseType = AZURE_MFA_SERVER_WAIT
			}
		}
		if name == "VerificationCode" {
			responseType = MFA_PROMPT
		}
	})
	return responseType, samlAssertion, nil
}

func updateFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	if !ok {
		return
	}

	typeValue, typeFound := s.Attr("type")
	hiddenAttr := typeFound && typeValue == "hidden"

	lname := strings.ToLower(name)
	if strings.Contains(lname, "user") {
		if !hiddenAttr {
			authForm.Add(name, user.Username)
		}
	} else if strings.Contains(lname, "email") {
		if !hiddenAttr {
			authForm.Add(name, user.Username)
		}
	} else if strings.Contains(lname, "pass") {
		if !hiddenAttr {
			authForm.Add(name, user.Password)
		}
	} else {
		updatePassthroughFormData(authForm, s)
	}
}

func updateOTPFormData(otpForm url.Values, s *goquery.Selection, token string) {
	name, ok := s.Attr("name")
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "security_code") {
		otpForm.Add(name, token)
	} else if strings.Contains(lname, "verificationcode") {
		otpForm.Add(name, token)
	} else if strings.Contains(lname, "challengequestionanswer") {
		otpForm.Add(name, token)
	} else {
		updatePassthroughFormData(otpForm, s)
	}

}

func updatePassthroughFormData(otpForm url.Values, s *goquery.Selection) {
	name, ok := s.Attr("name")
	if !ok {
		return
	}
	val, ok := s.Attr("value")
	if !ok {
		return
	}
	otpForm.Add(name, val)

}
