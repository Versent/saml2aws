package akamai

import (
	"bytes"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/prompter"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/provider"

	"encoding/json"
)

const (
	IdentifierDuoMfa   = "duo"
	IdentifierSmsMfa   = "sms"
	IdentifierEmailMfa = "email"
	IdentifierTotpMfa  = "totp"
)

var logger = logrus.WithField("provider", "akamai")

var (
	supportedMfaOptions = map[string]MfaUserOption{
		IdentifierDuoMfa:   {"DUO MFA authentication", "duo"},
		IdentifierSmsMfa:   {"SMS MFA authentication", "sms"},
		IdentifierEmailMfa: {"EMAIL MFA authentication", "email"},
		IdentifierTotpMfa:  {"TOTP MFA authentication", "totp"},
	}
)

type MfaUserOption struct {
	UserDisplayString string
	UserMfaOption     string
}

// Client is a wrapper representing a Akamai SAML client
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
	mfa    string
}

// AuthRequest represents an mfa Akamai request
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Navigate request for saml
type NavRequest struct {
	Hostname string `json:"hostname"`
}

type MfaPushRequest struct {
	Force bool   `json:"force"`
	Uuid  string `json:"uuid"`
}

type MfaTokenVerify struct {
	Category       string `json:"category"`
	Token          string `json:"token"`
	Uuid           string `json:"uuid"`
	DuoSigRequest  string `json:"sig_request"`
	DuoSigResponse string `json:"sig_response"`
}

// New creates a new Akamai client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// assign a response validator to ensure all responses are either success or a redirect
	// this is to avoid have explicit checks for every single response
	client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	return &Client{
		client: client,
		mfa:    idpAccount.MFA,
	}, nil
}

// Authenticate logs into Akamai and returns a SAML response
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var samlAssertion string

	akamaiURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building akamaiURL")
	}

	akamaiOrgHost := akamaiURL.Host

	akamaiQuery := akamaiURL.Query()
	akamaiSamlApp := string(akamaiQuery.Get("app"))

	// Get xsrf data and cookie by doing get request
	akamaiLoginURL := fmt.Sprintf("https://%s/", akamaiOrgHost)
	req, err := http.NewRequest("GET", akamaiLoginURL, nil)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	res, err := oc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login request")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
	}

	xsrfToken, ok := doc.Find("input[id=\"xsrf\"]").Attr("value")
	if !ok {
		return samlAssertion, errors.Wrap(err, "unable to locate xsrf token in html")
	}

	// Send login request to Akamai
	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password}
	authBody := new(bytes.Buffer)
	err = json.NewEncoder(authBody).Encode(authReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error encoding authreq")
	}
	authSubmitURL := fmt.Sprintf("https://%s/api/v1/login", akamaiOrgHost)

	loginReq, err := http.NewRequest("POST", authSubmitURL, authBody)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	loginReq.Header.Add("Content-Type", "application/json")
	loginReq.Header.Add("Accept", "application/json")
	loginReq.Header.Add("xsrf", string(xsrfToken))

	res, err = oc.client.Do(loginReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error login to EAA IDP")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)
	authStatus := gjson.Get(resp, "status").String()
	if authStatus != "200" {
		authFailReason := gjson.Get(resp, "msg").String()
		fmt.Printf("Login Failed %s\n", authFailReason)
		logger.Debug("Login Failed:", authFailReason)
		return samlAssertion, errors.Wrap(err, "Login Failure")
	}

	// Send saml navigate request to Akamai
	navReq := NavRequest{Hostname: akamaiSamlApp}
	navBody := new(bytes.Buffer)
	err = json.NewEncoder(navBody).Encode(navReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error encoding navreq")
	}
	navSubmitURL := fmt.Sprintf("https://%s/api/v2/apps/navigate", akamaiOrgHost)

	navloginReq, err := http.NewRequest("POST", navSubmitURL, navBody)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building navigation request")
	}
	navloginReq.Header.Add("Content-Type", "application/json")
	navloginReq.Header.Add("Accept", "application/json")
	navloginReq.Header.Add("xsrf", string(xsrfToken))

	res, err = oc.client.Do(navloginReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error while navigation request to EAA ")
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving response from navigate request")
	}

	mfaStatus := gjson.GetBytes(body, "mfa.status").String()
	if mfaStatus == "verify" {
		err = verifyMfa(oc, akamaiOrgHost, loginDetails, xsrfToken)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error verifying MFA")
		}
	} else if mfaStatus == "register" {
		fmt.Printf("MFA is enabled but not registered for user. Register MFA by accessing EAA IDP from Browser\n")
		logger.Debug("MFA is enabled but not registered for user")
		return samlAssertion, errors.Wrap(err, "register mfa by logging to IDP")
	}

	/* MFA is done call navigate again */
	navReq = NavRequest{Hostname: akamaiSamlApp}
	navBody = new(bytes.Buffer)
	err = json.NewEncoder(navBody).Encode(navReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error encoding authreq")
	}
	navSubmitURL = fmt.Sprintf("https://%s/api/v2/apps/navigate", akamaiOrgHost)

	navloginReq, err = http.NewRequest("POST", navSubmitURL, navBody)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error sending final navigate request")
	}
	navloginReq.Header.Add("Content-Type", "application/json")
	navloginReq.Header.Add("Accept", "application/json")
	navloginReq.Header.Add("xsrf", string(xsrfToken))

	res, err = oc.client.Do(navloginReq)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error navigate request to EAA ")
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving body from response")
	}

	/* saml assertion response from json of navigate */
	samlResponseHtml := gjson.GetBytes(body, "navigate.body").String()
	doc, err = goquery.NewDocumentFromReader(strings.NewReader(samlResponseHtml))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing saml response in document")
	}

	samlAssertion, ok = doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return samlAssertion, errors.Wrap(err, "unable to locate SAMLResponse in html")
	}

	logger.Debug("auth complete")
	return samlAssertion, nil
}

func verifyMfa(oc *Client, akamaiOrgHost string, loginDetails *creds.LoginDetails, xsrfToken string) error {

	/* Get supported MFA for this login */
	mfaConfigURL := fmt.Sprintf("https://%s/api/v1/config/mfa", akamaiOrgHost)
	mfaConfigReq, err := http.NewRequest("GET", mfaConfigURL, nil)
	if err != nil {
		return errors.Wrap(err, "error building mfa config request")
	}
	mfaConfigReq.Header.Add("Accept", "application/json")
	mfaConfigReq.Header.Add("xsrf", string(xsrfToken))
	res, err := oc.client.Do(mfaConfigReq)
	if err != nil {
		return errors.Wrap(err, "error mfa config request to EAA ")
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "error retrieving mfa config request")
	}

	mfaConfigData := gjson.GetBytes(body, "mfa.config.options")
	if mfaConfigData.Index == 0 {
		log.Println("Mfa Config option not found")
		return errors.Wrap(err, "Mfa not configured ")
	}

	/* Mfa config data present or not check otherwise return directly */
	mfaOption := 0
	var mfaOptions []MfaUserOption
	for _, name := range mfaConfigData.Array() {
		identifier := name.String()
		if val, ok := supportedMfaOptions[identifier]; ok {
			mfaOptions = append(mfaOptions, val)
		}
	}

	/* Get MFA token settings from IDP */
	mfaSettingURL := fmt.Sprintf("https://%s/api/v1/mfa/token/settings", akamaiOrgHost)
	mfaSettingReq, err := http.NewRequest("GET", mfaSettingURL, nil)
	if err != nil {
		return errors.Wrap(err, "error building mfa setting request")
	}
	mfaSettingReq.Header.Add("Accept", "application/json")
	mfaSettingReq.Header.Add("xsrf", string(xsrfToken))
	res, err = oc.client.Do(mfaSettingReq)
	if err != nil {
		return errors.Wrap(err, "error mfa setting request to EAA ")
	}
	mfaSettingData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "error retrieving body from response")
	}

	var mfaDisplayOptions []string
	var mfaUserOption string
	var mfaConfiguredSupported int

	if oc.mfa != "Auto" {
		mfaUserOption = strings.ToLower(oc.mfa)
		for _, val := range mfaOptions {
			if mfaUserOption == val.UserMfaOption {
				mfaDisplayOptions = nil
				mfaConfiguredSupported = 1
				break
			}
			mfaDisplayOptions = append(mfaDisplayOptions, val.UserDisplayString)
		}

		mfaDisplayNum := len(mfaDisplayOptions)
		if mfaDisplayNum > 1 {
			mfaOption = prompter.Choose("Select which MFA option to use", mfaDisplayOptions)
			mfaUserOption = mfaOptions[mfaOption].UserMfaOption
		} else if mfaDisplayNum == 1 {
			mfaUserOption = mfaOptions[1].UserMfaOption
		} else if mfaDisplayNum == 0 && mfaConfiguredSupported != 1 {
			return errors.New("unsupported mfa provider")
		}
	} else {
		mfaUserOption = gjson.GetBytes(mfaSettingData, "mfa.settings.preferred.option").String()
	}

	if _, ok := supportedMfaOptions[mfaUserOption]; !ok {
		return errors.New("unsupported mfa provider")
	}

	/* specific mfa */
	switch mfa := mfaUserOption; mfa {

	case IdentifierSmsMfa, IdentifierEmailMfa, IdentifierTotpMfa:

		/* 1. Get MFA UUID */
		mfaUuid := fmt.Sprintf("mfa.settings.%s.0.uuid", mfa)
		uuidMfa := gjson.GetBytes(mfaSettingData, mfaUuid).String()

		/* 2.Push MFA */
		var mfaApi = mfa
		if mfa == IdentifierSmsMfa {
			mfaApi = "phone"
		}

		var mfaResStatus string
		if mfa == IdentifierSmsMfa || mfa == IdentifierEmailMfa {
			mfaPushURL := fmt.Sprintf("https://%s/api/v1/mfa/user/%s/token/push", akamaiOrgHost, mfaApi)
			mfaPushData := MfaPushRequest{Force: false, Uuid: uuidMfa}
			mfaPushBody := new(bytes.Buffer)
			err = json.NewEncoder(mfaPushBody).Encode(mfaPushData)
			if err != nil {
				return errors.Wrap(err, "error encoding mfa push data ")
			}

			mfaPushReq, err := http.NewRequest("POST", mfaPushURL, mfaPushBody)
			if err != nil {
				return errors.Wrap(err, "error building mfa push request")
			}

			mfaPushReq.Header.Add("Content-Type", "application/json")
			mfaPushReq.Header.Add("Accept", "application/json")
			mfaPushReq.Header.Add("xsrf", string(xsrfToken))

			res, err = oc.client.Do(mfaPushReq)
			if err != nil {
				return errors.Wrap(err, "error while sending MFA push code ")
			}

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return errors.Wrap(err, "error retrieving MFA push response ")
			}

			mfaResStatus := gjson.GetBytes(body, "status").String()

			if mfaResStatus != "200" {
				return errors.Wrap(err, "Unable to send mfa token")
			}

		}
		/* 3. Verify MFA */

		verifyCode := prompter.StringRequired("Enter MFA verification code")

		mfaVerifyURL := fmt.Sprintf("https://%s/api/v1/mfa/user/%s/token/verify", akamaiOrgHost, mfaApi)
		mfaVerifyData := MfaTokenVerify{Category: mfa, Token: verifyCode, Uuid: uuidMfa}
		mfaVerifyBody := new(bytes.Buffer)
		err = json.NewEncoder(mfaVerifyBody).Encode(mfaVerifyData)
		if err != nil {
			return errors.Wrap(err, "error encoding mfa verify req")
		}
		mfaVerifyReq, err := http.NewRequest("POST", mfaVerifyURL, mfaVerifyBody)
		if err != nil {
			return errors.Wrap(err, "error creating mfa verification request")
		}

		mfaVerifyReq.Header.Add("Content-Type", "application/json")
		mfaVerifyReq.Header.Add("Accept", "application/json")
		mfaVerifyReq.Header.Add("xsrf", string(xsrfToken))

		res, err = oc.client.Do(mfaVerifyReq)
		if err != nil {
			return errors.Wrap(err, "error verifying mfa to EAA ")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "error retrieving mfa verify response")
		}

		mfaResStatus = gjson.GetBytes(body, "status").String()
		if mfaResStatus != "200" {
			return errors.Wrap(err, "Unable to verify mfa token")
		}

		return nil

	case IdentifierDuoMfa:

		duoSettings := fmt.Sprintf("mfa.settings.%s.0", mfa)

		duoHost := gjson.GetBytes(mfaSettingData, duoSettings).Get("duo_host").String()
		duoSignature := gjson.GetBytes(mfaSettingData, duoSettings).Get("token").String()
		duoSignatures := strings.Split(duoSignature, ":")

		//duoSignatures[0] = TX
		//duoSignatures[1] = APP

		// initiate duo mfa to get sid
		duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

		duoForm := url.Values{}
		duoForm.Add("parent", fmt.Sprintf("https://%s/#/token", akamaiOrgHost))
		duoForm.Add("java_version", "")
		duoForm.Add("java_version", "")
		duoForm.Add("flash_version", "")
		duoForm.Add("screen_resolution_width", "1440")
		duoForm.Add("screen_resolution_height", "900")
		duoForm.Add("color_depth", "24")

		req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return errors.Wrap(err, "error building duo request")
		}
		q := req.URL.Query()
		q.Add("tx", duoSignatures[0])
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return errors.Wrap(err, "error sending duo request")
		}

		//try to extract sid
		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			return errors.Wrap(err, "error parsing document from duo")
		}

		duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
		if !ok {
			return errors.Wrap(err, "unable to locate sid in duo response")
		}
		duoSID = html.UnescapeString(duoSID)

		//prompt for mfa type
		//only supporting push or passcode for now
		var token string

		var duoMfaOptions = []string{
			"Duo Push",
			"Passcode",
		}

		duoMfaOption := 0

		if loginDetails.DuoMFAOption == "Duo Push" {
			duoMfaOption = 0
		} else if loginDetails.DuoMFAOption == "Passcode" {
			duoMfaOption = 1
		} else {
			duoMfaOption = prompter.Choose("Select a DUO MFA Option", duoMfaOptions)
		}

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
			return errors.Wrap(err, "error building duo prompt request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return errors.Wrap(err, "error retrieving duo prompt request")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "error retrieving duo prompt response")
		}

		resp := string(body)

		duoTxStat := gjson.Get(resp, "stat").String()
		duoTxID := gjson.Get(resp, "response.txid").String()
		if duoTxStat != "OK" {
			return errors.Wrap(err, "error authenticating duo mfa device")
		}

		// get duo cookie
		duoSubmitURL = fmt.Sprintf("https://%s/frame/status", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("txid", duoTxID)

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return errors.Wrap(err, "error building duo status request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return errors.Wrap(err, "error sending duo status request")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "error retrieving duo status response")
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
					return errors.Wrap(err, "error building authentication request")
				}

				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				res, err = oc.client.Do(req)
				if err != nil {
					return errors.Wrap(err, "error retrieving verify response")
				}

				body, err = ioutil.ReadAll(res.Body)
				if err != nil {
					return errors.Wrap(err, "error retrieving body from response")
				}

				resp := string(body)

				duoTxResult = gjson.Get(resp, "response.result").String()
				duoResultURL = gjson.Get(resp, "response.result_url").String()

				log.Println(gjson.Get(resp, "response.status").String())

				if duoTxResult == "FAILURE" {
					return errors.Wrap(err, "failed to authenticate device")
				}

				if duoTxResult == "SUCCESS" {
					break
				}
			}
		}

		duoRequestURL := fmt.Sprintf("https://%s%s", duoHost, duoResultURL)
		req, err = http.NewRequest("POST", duoRequestURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return errors.Wrap(err, "error constructing request object to result url")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = oc.client.Do(req)
		if err != nil {
			return errors.Wrap(err, "error retrieving duo result response")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "duoResultSubmit: error retrieving body from response")
		}

		resp = string(body)
		duoTxCookie := gjson.Get(resp, "response.cookie").String()
		if duoTxCookie == "" {
			return errors.Wrap(err, "duoResultSubmit: Unable to get response.cookie")
		}

		// callback to Akamai to verify

		mfaVerifyURL := fmt.Sprintf("https://%s/api/v1/mfa/user/%s/token/verify", akamaiOrgHost, mfa)
		mfaDuoSigResponse := fmt.Sprintf("%s:%s", duoTxCookie, duoSignatures[1])
		mfaVerifyData := MfaTokenVerify{Category: mfa, Uuid: mfa,
			DuoSigRequest: duoSignature, DuoSigResponse: mfaDuoSigResponse}
		mfaVerifyBody := new(bytes.Buffer)
		err = json.NewEncoder(mfaVerifyBody).Encode(mfaVerifyData)
		if err != nil {
			return errors.Wrap(err, "error encoding duo mfa verify req")
		}
		mfaVerifyReq, err := http.NewRequest("POST", mfaVerifyURL, mfaVerifyBody)
		if err != nil {
			return errors.Wrap(err, "error creating duo mfa verification request")
		}

		mfaVerifyReq.Header.Add("Content-Type", "application/json")
		mfaVerifyReq.Header.Add("Accept", "application/json")
		mfaVerifyReq.Header.Add("xsrf", string(xsrfToken))

		res, err = oc.client.Do(mfaVerifyReq)
		if err != nil {
			return errors.Wrap(err, "error sending duo mfa request to EAA ")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.Wrap(err, "error retrieving duo mfa response ")
		}

		mfaResStatus := gjson.GetBytes(body, "status").String()
		if mfaResStatus != "200" {
			return errors.Wrap(err, "Unable to verify mfa token")
		}

		return nil

	}

	return errors.New("no mfa options provided")

}
