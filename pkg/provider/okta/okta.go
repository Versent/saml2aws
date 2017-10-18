package okta

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	prompt "github.com/segmentio/go-prompt"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"

	"encoding/json"

	"golang.org/x/net/publicsuffix"
)

// Client is a wrapper representing a Okta SAML client
type Client struct {
	client *http.Client
}

// AuthRequest represents an mfa okta request
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// VerifyRequest represents an mfa verify request
type VerifyRequest struct {
	StateToken string `json:"stateToken"`
}

// New creates a new Okta client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify},
	}

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: tr, Jar: jar}

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into Okta and returns a SAML response
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	var samlAssertion string

	oktaEntryURL := fmt.Sprintf("https://%s", loginDetails.Hostname)
	oktaURL, err := url.Parse(oktaEntryURL)
	oktaOrgHost := oktaURL.Host

	//authenticate via okta api
	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password}
	authBody := new(bytes.Buffer)
	json.NewEncoder(authBody).Encode(authReq)

	authSubmitURL := fmt.Sprintf("https://%s/api/v1/authn", oktaOrgHost)

	req, err := http.NewRequest("POST", authSubmitURL, authBody)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving auth response")
	}

	body, err := ioutil.ReadAll(res.Body)
	resp := string(body)

	stateToken := gjson.Get(resp, "stateToken").String()
	authStatus := gjson.Get(resp, "status").String()

	// mfa required
	if authStatus == "MFA_REQUIRED" {

		deviceID := gjson.Get(resp, "_embedded.factors.0.id").String()
		oktaVerify := gjson.Get(resp, "_embedded.factors.0._links.verify.href").String()
		mfaProvider := gjson.Get(resp, "_embedded.factors.0.provider").String()

		if mfaProvider != "DUO" {
			return samlAssertion, errors.Wrap(err, "unsupported mfa provider")
		}

		// get duo host, signature & callback
		verifyReq := VerifyRequest{StateToken: stateToken}
		verifyBody := new(bytes.Buffer)
		json.NewEncoder(verifyBody).Encode(verifyReq)

		req, err := http.NewRequest("POST", oktaVerify, verifyBody)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building verify request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")

		res, err := oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		resp = string(body)

		duoHost := gjson.Get(resp, "_embedded.factor._embedded.verification.host").String()
		duoSignature := gjson.Get(resp, "_embedded.factor._embedded.verification.signature").String()
		duoSiguatres := strings.Split(duoSignature, ":")
		//duoSignatures[0] = TX
		//duoSignatures[1] = APP
		duoCallback := gjson.Get(resp, "_embedded.factor._embedded.verification._links.complete.href").String()

		// initiate duo mfa to get sid
		duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

		duoForm := url.Values{}
		duoForm.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", oktaOrgHost))
		duoForm.Add("java_version", "")
		duoForm.Add("java_version", "")
		duoForm.Add("flash_version", "")
		duoForm.Add("screen_resolution_width", "3008")
		duoForm.Add("screen_resolution_height", "1692")
		duoForm.Add("color_depth", "24")

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}
		q := req.URL.Query()
		q.Add("tx", duoSiguatres[0])
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		//try to extract sid
		doc, err := goquery.NewDocumentFromResponse(res)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error parsing document")
		}

		duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
		if !ok {
			return samlAssertion, errors.Wrap(err, "unable to locate saml response")
		}
		duoSID = html.UnescapeString(duoSID)

		//prompt for mfa type
		//only supporting push or passcode for now
		var token string

		var mfaOptions = []string{
			"Passcode",
			"Duo Push",
		}

		mfaOption := prompt.Choose("Select a DUO MFA Option", mfaOptions)

		if mfaOptions[mfaOption] == "Passcode" {
			//get users DUO MFA Token
			token = prompt.StringRequired("Enter passcode")
		}

		// send mfa auth request
		duoSubmitURL = fmt.Sprintf("https://%s/frame/prompt", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("device", "phone1")
		duoForm.Add("factor", mfaOptions[mfaOption])
		duoForm.Add("out_of_date", "false")
		if mfaOptions[mfaOption] == "Passcode" {
			duoForm.Add("passcode", token)
		}

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		resp = string(body)

		duoTxStat := gjson.Get(resp, "stat").String()
		duoTxID := gjson.Get(resp, "response.txid").String()
		if duoTxStat != "OK" {
			return samlAssertion, errors.Wrap(err, "error authenticating mfa device")
		}

		// get duo cookie
		duoSubmitURL = fmt.Sprintf("https://%s/frame/status", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("txid", duoTxID)

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		resp = string(body)

		duoTxResult := gjson.Get(resp, "response.result").String()
		duoTxCookie := gjson.Get(resp, "response.cookie").String()

		fmt.Println(gjson.Get(resp, "response.status").String())

		if duoTxResult != "SUCCESS" {
			//poll as this is likely a push request
			for {
				time.Sleep(3 * time.Second)

				req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
				if err != nil {
					return samlAssertion, errors.Wrap(err, "error building authentication request")
				}

				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				res, err = oc.client.Do(req)
				if err != nil {
					return samlAssertion, errors.Wrap(err, "error retrieving verify response")
				}

				body, err = ioutil.ReadAll(res.Body)
				resp := string(body)

				duoTxResult = gjson.Get(resp, "response.result").String()
				duoTxCookie = gjson.Get(resp, "response.cookie").String()

				fmt.Println(gjson.Get(resp, "response.status").String())

				if duoTxResult == "FAILURE" {
					return samlAssertion, errors.Wrap(err, "failed to authenticate device")
				}

				if duoTxResult == "SUCCESS" {
					break
				}
			}
		}

		// callback to okta with cookie
		oktaForm := url.Values{}
		oktaForm.Add("id", deviceID)
		oktaForm.Add("stateToken", stateToken)
		oktaForm.Add("sig_response", fmt.Sprintf("%s:%s", duoTxCookie, duoSiguatres[1]))

		req, err = http.NewRequest("POST", duoCallback, strings.NewReader(oktaForm.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		// extract okta session token

		verifyReq = VerifyRequest{StateToken: stateToken}
		verifyBody = new(bytes.Buffer)
		json.NewEncoder(verifyBody).Encode(verifyReq)

		req, err = http.NewRequest("POST", oktaVerify, verifyBody)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building verify request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("X-Okta-XsrfToken", "")

		res, err = oc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		resp = string(body)

	}

	oktaSessionToken := gjson.Get(resp, "sessionToken").String()

	//now call saml endpoint
	oktaSessionRedirectURL := fmt.Sprintf("https://%s/login/sessionCookieRedirect", oktaOrgHost)

	req, err = http.NewRequest("GET", oktaSessionRedirectURL, nil)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("checkAccountSetupComplete", "true")
	q.Add("token", oktaSessionToken)
	q.Add("redirectUrl", oktaEntryURL)
	req.URL.RawQuery = q.Encode()

	res, err = oc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving verify response")
	}

	//try to extract SAMLResponse
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
	}

	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return samlAssertion, errors.Wrap(err, "unable to locate saml response")
	}

	return samlAssertion, nil
}
