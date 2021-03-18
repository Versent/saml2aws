package shibboleth

import (
	"crypto/tls"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

// Client wrapper around Shibboleth enabling authentication and retrieval of assertions
type Client struct {
	provider.ValidateBase

	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new Shibboleth client
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

// Authenticate authenticate to Shibboleth and return the data from the body of the SAML assertion.
func (sc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var authSubmitURL string
	var samlAssertion string

	shibbolethURL := fmt.Sprintf("%s/idp/profile/SAML2/Unsolicited/SSO?providerId=%s", loginDetails.URL, sc.idpAccount.AmazonWebservicesURN)

	res, err := sc.client.Get(shibbolethURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
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

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.URL.Host = res.Request.URL.Host
	req.URL.Scheme = res.Request.URL.Scheme

	res, err = sc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form results")
	}

	switch sc.idpAccount.MFA {
	case "Auto":
		b, _ := ioutil.ReadAll(res.Body)

		mfaRes, err := verifyMfa(sc, loginDetails.URL, string(b))
		if err != nil {
			return mfaRes.Status, errors.Wrap(err, "error verifying MFA")
		}

		res = mfaRes

	}

	samlAssertion, err = extractSamlResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error extracting SAMLResponse blob from final Shibboleth response")
	}

	return samlAssertion, nil
}

func updateFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	authForm.Add("_eventId_proceed", "")

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

func verifyMfa(oc *Client, shibbolethHost string, resp string) (*http.Response, error) {

	duoHost, postAction, tx, app, csrfToken := parseTokens(resp)

	parent := fmt.Sprintf(shibbolethHost + postAction)

	duoTxCookie, err := verifyDuoMfa(oc, duoHost, parent, tx)
	if err != nil {
		return nil, errors.Wrap(err, "error when interacting with Duo iframe")
	}

	idpForm := url.Values{}
	idpForm.Add("_eventId", "proceed")
	idpForm.Add("sig_response", duoTxCookie+":"+app)
	idpForm.Add("csrf_token", csrfToken)

	req, err := http.NewRequest("POST", parent, strings.NewReader(idpForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error posting multi-factor verification to shibboleth server")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	return res, nil
}

func verifyDuoMfa(oc *Client, duoHost string, parent string, tx string) (string, error) {
	// initiate duo mfa to get sid
	duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

	duoForm := url.Values{}
	duoForm.Add("parent", parent)
	duoForm.Add("java_version", "")
	duoForm.Add("java_version", "")
	duoForm.Add("flash_version", "")
	duoForm.Add("screen_resolution_width", "3008")
	duoForm.Add("screen_resolution_height", "1692")
	duoForm.Add("color_depth", "24")

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("tx", tx)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving verify response")
	}

	// retrieve response from post
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	// Duo cookie is returned here if mfa bypassed - immediatly return it if found
	duoTxCookie, ok := doc.Find("input[name=\"js_cookie\"]").Attr("value")
	if ok {
		if duoTxCookie == "" {
			return "", errors.Wrap(err, "duoMfaBypass: invalid response cookie")
		}
		return duoTxCookie, nil
	}

	// Duo cookie not found - continue with full MFA transaction
	duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
	if !ok {
		return "", errors.Wrap(err, "unable to locate saml response")
	}
	duoSID = html.UnescapeString(duoSID)

	//prompt for mfa type
	//supporting push, call, and passcode for now

	var token string

	var duoMfaOptions = []string{
		"Duo Push",
		"Phone Call",
		"Passcode",
	}

	duoMfaOption := prompter.Choose("Select a DUO MFA Option", duoMfaOptions)

	if duoMfaOptions[duoMfaOption] == "Passcode" {
		//get users DUO MFA Token
		token = prompter.StringRequired("Enter passcode")
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

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

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
	duoResultURL := gjson.Get(resp, "response.result_url").String()

	log.Println(gjson.Get(resp, "response.status").String())

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
			duoResultURL = gjson.Get(resp, "response.result_url").String()

			log.Println(gjson.Get(resp, "response.status").String())

			if duoTxResult == "FAILURE" {
				return "", errors.Wrap(err, "failed to authenticate device")
			}

			if duoTxResult == "SUCCESS" {
				break
			}
		}
	}

	duoRequestURL := fmt.Sprintf("https://%s%s", duoHost, duoResultURL)
	req, err = http.NewRequest("POST", duoRequestURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error constructing request object to result url")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving duo result response")
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "duoResultSubmit: error retrieving body from response")
	}

	resp = string(body)

	duoTxCookie = gjson.Get(resp, "response.cookie").String()
	if duoTxCookie == "" {
		return "", errors.Wrap(err, "duoResultSubmit: Unable to get response.cookie")
	}

	return duoTxCookie, nil
}

func parseTokens(blob string) (string, string, string, string, string) {
	hostRgx := regexp.MustCompile(`data-host=\"(.*?)\"`)
	sigRgx := regexp.MustCompile(`data-sig-request=\"(.*?)\"`)
	dpaRgx := regexp.MustCompile(`data-post-action=\"(.*?)\"`)
	csrfRgx := regexp.MustCompile(`name=\"csrf_token\" value=\"(.*?)\"`)

	dataSigRequest := sigRgx.FindStringSubmatch(blob)
	duoHost := hostRgx.FindStringSubmatch(blob)
	postAction := dpaRgx.FindStringSubmatch(blob)

	// extract the Shibboleth v4 CSRF token, if present
	csrfToken := ""
	csrfTokenMatch := csrfRgx.FindStringSubmatch(blob)
	if len(csrfTokenMatch) != 0 {
		csrfToken = csrfTokenMatch[1]
	}

	duoSignatures := strings.Split(dataSigRequest[1], ":")
	return duoHost[1], postAction[1], duoSignatures[0], duoSignatures[1], csrfToken
}

func extractSamlResponse(res *http.Response) (string, error) {
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "extractSamlResponse: error retrieving body from response")
	}

	samlRgx := regexp.MustCompile(`name=\"SAMLResponse\" value=\"(.*?)\"/>`)
	samlResponseValue := samlRgx.FindStringSubmatch(string(body))
	return samlResponseValue[1], nil
}
