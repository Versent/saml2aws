package okta

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	prompt "github.com/segmentio/go-prompt"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/dump"
	"github.com/versent/saml2aws/pkg/prompter"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider"

	"encoding/json"
)

const (
	IdentifierDuoMfa  = "DUO WEB"
	IdentifierSmsMfa  = "OKTA SMS"
	IdentifierPushMfa = "OKTA PUSH"
	IdentifierTotpMfa = "GOOGLE TOKEN:SOFTWARE:TOTP"
)

var logger = logrus.WithField("provider", "okta")

var (
	supportedMfaOptions = map[string]string{
		IdentifierDuoMfa:  "DUO MFA authentication",
		IdentifierSmsMfa:  "SMS MFA authentication",
		IdentifierPushMfa: "PUSH MFA authentication",
		IdentifierTotpMfa: "TOTP MFA authentication",
	}
)

// OktaClient is a wrapper representing a Okta SAML client
type Client struct {
	client   *provider.HTTPClient
	prompter prompter.Prompter
}

// AuthRequest represents an mfa okta request
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// VerifyRequest represents an mfa verify request
type VerifyRequest struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode,omitempty"`
}

// New creates a new Okta client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:   client,
		prompter: prompter.NewCli(),
	}, nil
}

// Authenticate logs into Okta and returns a SAML response
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	var samlAssertion string

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building oktaURL")
	}

	oktaOrgHost := oktaURL.Host

	//authenticate via okta api
	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password}
	authBody := new(bytes.Buffer)
	err = json.NewEncoder(authBody).Encode(authReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error encoding authreq")
	}

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

	logger.WithField("status", res.StatusCode).WithField("authSubmitURL", authSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

	authStatus := gjson.Get(resp, "status").String()
	oktaSessionToken := gjson.Get(resp, "sessionToken").String()

	// mfa required
	if authStatus == "MFA_REQUIRED" {
		oktaSessionToken, err = verifyMfa(oc, oktaOrgHost, resp)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error verifying MFA")
		}
	}

	//now call saml endpoint
	oktaSessionRedirectURL := fmt.Sprintf("https://%s/login/sessionCookieRedirect", oktaOrgHost)

	req, err = http.NewRequest("GET", oktaSessionRedirectURL, nil)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("checkAccountSetupComplete", "true")
	q.Add("token", oktaSessionToken)
	q.Add("redirectUrl", loginDetails.URL)
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

func parseMfaIdentifer(json string, arrayPosition int) string {
	mfaProvider := gjson.Get(json, fmt.Sprintf("_embedded.factors.%d.provider", arrayPosition)).String()
	factorType := strings.ToUpper(gjson.Get(json, fmt.Sprintf("_embedded.factors.%d.factorType", arrayPosition)).String())
	return fmt.Sprintf("%s %s", mfaProvider, factorType)
}

func verifyMfa(oc *Client, oktaOrgHost string, resp string) (string, error) {

	stateToken := gjson.Get(resp, "stateToken").String()

	// choose an mfa option if there are multiple enabled
	mfaOption := 0
	var mfaOptions []string
	for i := range gjson.Get(resp, "_embedded.factors").Array() {
		identifier := parseMfaIdentifer(resp, i)
		if val, ok := supportedMfaOptions[identifier]; ok {
			mfaOptions = append(mfaOptions, val)
		} else {
			mfaOptions = append(mfaOptions, "UNSUPPORTED: "+identifier)
		}
	}
	if len(mfaOptions) > 1 {
		mfaOption = prompt.Choose("Select which MFA option to use", mfaOptions)
	}

	factorID := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d.id", mfaOption)).String()
	oktaVerify := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d._links.verify.href", mfaOption)).String()
	mfaIdentifer := parseMfaIdentifer(resp, mfaOption)

	logger.WithField("factorID", factorID).WithField("oktaVerify", oktaVerify).WithField("mfaIdentifer", mfaIdentifer).Debug("MFA")

	if _, ok := supportedMfaOptions[mfaIdentifer]; !ok {
		return "", errors.New("unsupported mfa provider")
	}

	// get signature & callback
	verifyReq := VerifyRequest{StateToken: stateToken}
	verifyBody := new(bytes.Buffer)
	err := json.NewEncoder(verifyBody).Encode(verifyReq)
	if err != nil {
		return "", errors.Wrap(err, "error encoding verifyReq")
	}

	req, err := http.NewRequest("POST", oktaVerify, verifyBody)
	if err != nil {
		return "", errors.Wrap(err, "error building verify request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving verify response")
	}

	logger.WithField("status", res.StatusCode).WithField("res", dump.ResponseString(res)).Debug("POST")

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}
	resp = string(body)

	switch mfa := mfaIdentifer; mfa {
	case IdentifierSmsMfa, IdentifierTotpMfa:
		verifyCode := prompt.StringRequired("Enter verification code")
		tokenReq := VerifyRequest{StateToken: stateToken, PassCode: verifyCode}
		tokenBody := new(bytes.Buffer)
		json.NewEncoder(tokenBody).Encode(tokenReq)

		req, err = http.NewRequest("POST", oktaVerify, tokenBody)
		if err != nil {
			return "", errors.Wrap(err, "error building token post request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")

		res, err := oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving token post response")
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}

		resp = string(body)

		return gjson.Get(resp, "sessionToken").String(), nil

	case IdentifierPushMfa:

		fmt.Printf("\nWaiting for approval, please check your Okta Verify app ...")

		// loop until success, error, or timeout
		for {

			res, err = oc.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving verify response")
			}

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving body from response")
			}

			// on 'success' status
			if gjson.Get(string(body), "status").String() == "SUCCESS" {
				fmt.Printf(" Approved\n\n")
				return gjson.Get(string(body), "sessionToken").String(), nil
			}

			// otherwise probably still waiting
			switch gjson.Get(string(body), "factorResult").String() {

			case "WAITING":
				time.Sleep(1000)
				fmt.Printf(".")
				logger.Debug("Waiting for user to authorize login")

			case "TIMEOUT":
				fmt.Printf(" Timeout\n")
				return "", errors.New("User did not accept MFA in time")

			case "REJECTED":
				fmt.Printf(" Rejected\n")
				return "", errors.New("MFA rejected by user")

			default:
				fmt.Printf(" Error\n")
				return "", errors.New("Unsupported response from Okta, please raise ticket with saml2aws")

			}

		}

	case IdentifierDuoMfa:
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
			return "", errors.Wrap(err, "error building authentication request")
		}
		q := req.URL.Query()
		q.Add("tx", duoSiguatres[0])
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		//try to extract sid
		doc, err := goquery.NewDocumentFromResponse(res)
		if err != nil {
			return "", errors.Wrap(err, "error parsing document")
		}

		duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
		if !ok {
			return "", errors.Wrap(err, "unable to locate saml response")
		}
		duoSID = html.UnescapeString(duoSID)

		//prompt for mfa type
		//only supporting push or passcode for now
		var token string

		var duoMfaOptions = []string{
			"Passcode",
			"Duo Push",
		}

		duoMfaOption := prompt.Choose("Select a DUO MFA Option", duoMfaOptions)

		if duoMfaOptions[duoMfaOption] == "Passcode" {
			//get users DUO MFA Token
			token = prompt.StringRequired("Enter passcode")
		}

		// send mfa auth request
		duoSubmitURL = fmt.Sprintf("https://%s/frame/prompt", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("device", "phone1")
		duoForm.Add("factor", duoMfaOptions[duoMfaOption])
		duoForm.Add("out_of_date", "false")
		if duoMfaOptions[duoMfaOption] == "Passcode" {
			duoForm.Add("passcode", token)
		}

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}

		resp = string(body)

		duoTxStat := gjson.Get(resp, "stat").String()
		duoTxID := gjson.Get(resp, "response.txid").String()
		if duoTxStat != "OK" {
			return "", errors.Wrap(err, "error authenticating mfa device")
		}

		// get duo cookie
		duoSubmitURL = fmt.Sprintf("https://%s/frame/status", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("txid", duoTxID)

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}

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
					return "", errors.Wrap(err, "error building authentication request")
				}

				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				res, err = oc.client.Do(req)
				if err != nil {
					return "", errors.Wrap(err, "error retrieving verify response")
				}

				body, err = ioutil.ReadAll(res.Body)
				if err != nil {
					return "", errors.Wrap(err, "error retrieving body from response")
				}

				resp := string(body)

				duoTxResult = gjson.Get(resp, "response.result").String()
				duoTxCookie = gjson.Get(resp, "response.cookie").String()

				fmt.Println(gjson.Get(resp, "response.status").String())

				if duoTxResult == "FAILURE" {
					return "", errors.Wrap(err, "failed to authenticate device")
				}

				if duoTxResult == "SUCCESS" {
					break
				}
			}
		}

		// callback to okta with cookie
		oktaForm := url.Values{}
		oktaForm.Add("id", factorID)
		oktaForm.Add("stateToken", stateToken)
		oktaForm.Add("sig_response", fmt.Sprintf("%s:%s", duoTxCookie, duoSiguatres[1]))

		req, err = http.NewRequest("POST", duoCallback, strings.NewReader(oktaForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		// extract okta session token

		verifyReq = VerifyRequest{StateToken: stateToken}
		verifyBody = new(bytes.Buffer)
		json.NewEncoder(verifyBody).Encode(verifyReq)

		req, err = http.NewRequest("POST", oktaVerify, verifyBody)
		if err != nil {
			return "", errors.Wrap(err, "error building verify request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("X-Okta-XsrfToken", "")

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}

		resp = string(body)
		return gjson.Get(resp, "sessionToken").String(), nil
	}

	// catch all
	return "", errors.New("no mfa options provided")

}
