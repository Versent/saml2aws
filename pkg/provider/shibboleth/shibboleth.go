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
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "shibboleth")

// Client wrapper around Shibboleth enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new Shibboleth client
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

// Authenticate authenticate to Shibboleth and return the data from the body of the SAML assertion.
func (sc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var authSubmitURL string
	var samlAssertion string

	shibbolethURL := fmt.Sprintf("%s/idp/profile/SAML2/Unsolicited/SSO?providerId=%s", loginDetails.URL, sc.idpAccount.AmazonWebservicesURN)

	res, err := sc.client.Get(shibbolethURL)
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
			return mfaRes.Status, errors.Wrap(err, "error verifying MFA results")
		}

		doc, err = goquery.NewDocumentFromResponse(mfaRes)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving mfa form results")
		}
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

	tx, app, duoHost, dpa := parseTokens(resp)

	// initiate duo mfa to get sid
	duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

	duoForm := url.Values{}
	duoForm.Add("parent", dpa)
	duoForm.Add("java_version", "")
	duoForm.Add("java_version", "")
	duoForm.Add("flash_version", "")
	duoForm.Add("screen_resolution_width", "3008")
	duoForm.Add("screen_resolution_height", "1692")
	duoForm.Add("color_depth", "24")

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("tx", tx)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	//try to extract sid
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing document")
	}

	duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
	if !ok {
		return nil, errors.Wrap(err, "unable to locate saml response")
	}
	duoSID = html.UnescapeString(duoSID)

	//prompt for mfa type
	//only supporting push or passcode for now
	var token string

	var duoMfaOptions = []string{
		"Duo Push",
		"Passcode",
		"Phone Call",
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
		return nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body from response")
	}

	resp = string(body)

	duoTxStat := gjson.Get(resp, "stat").String()
	duoTxID := gjson.Get(resp, "response.txid").String()
	if duoTxStat != "OK" {
		return nil, errors.Wrap(err, "error authenticating mfa device")
	}

	// 	// get duo cookie
	duoSubmitURL = fmt.Sprintf("https://%s/frame/status", duoHost)

	duoForm = url.Values{}
	duoForm.Add("sid", duoSID)
	duoForm.Add("txid", duoTxID)

	req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body from response")
	}

	resp = string(body)

	duoTxResult := gjson.Get(resp, "response.result").String()
	duoTxCookie := gjson.Get(resp, "response.cookie").String()

	if duoTxResult != "SUCCESS" {
		//poll as this is likely a push request
		for {
			time.Sleep(3 * time.Second)

			req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
			if err != nil {
				return nil, errors.Wrap(err, "error building authentication request")
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			res, err = oc.client.Do(req)
			if err != nil {
				return nil, errors.Wrap(err, "error retrieving verify response")
			}

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return nil, errors.Wrap(err, "error retrieving body from response")
			}

			resp := string(body)

			duoTxResult = gjson.Get(resp, "response.result").String()
			duoTxCookie = gjson.Get(resp, "response.cookie").String()

			fmt.Println(gjson.Get(resp, "response.status").String())

			if duoTxResult == "FAILURE" {
				return nil, errors.Wrap(err, "failed to authenticate device")
			}

			if duoTxResult == "SUCCESS" {
				break
			}
		}
	}

	idpForm := url.Values{}
	idpForm.Add("_eventId", "proceed")
	idpForm.Add("sig_response", duoTxCookie+":"+app)

	req, err = http.NewRequest("POST", dpa, strings.NewReader(idpForm.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.URL.Scheme = "https"
	req.URL.Host = strings.Replace(shibbolethHost, "https://", "", -1)

	res, err = oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	return res, errors.New("no mfa options provided")
}

func parseTokens(blob string) (string, string, string, string) {
	hostRgx := regexp.MustCompile(`data-host=\"(.*?)\"`)
	sigRgx := regexp.MustCompile(`data-sig-request=\"(.*?)\"`)
	dpaRgx := regexp.MustCompile(`data-post-action=\"(.*?)\"`)

	rs := sigRgx.FindStringSubmatch(blob)
	host := hostRgx.FindStringSubmatch(blob)
	dpa := dpaRgx.FindStringSubmatch(blob)

	duoSignatures := strings.Split(rs[1], ":")
	return duoSignatures[0], duoSignatures[1], host[1], dpa[1]
}
