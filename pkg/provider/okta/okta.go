package okta

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/marshallbrekka/go-u2fhost"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/page"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
	"golang.org/x/net/publicsuffix"
)

const (
	IdentifierDuoMfa          = "DUO WEB"
	IdentifierSmsMfa          = "OKTA SMS"
	IdentifierPushMfa         = "OKTA PUSH"
	IdentifierTotpMfa         = "GOOGLE TOKEN:SOFTWARE:TOTP"
	IdentifierOktaTotpMfa     = "OKTA TOKEN:SOFTWARE:TOTP"
	IdentifierSymantecTotpMfa = "SYMANTEC TOKEN"
	IdentifierFIDOWebAuthn    = "FIDO WEBAUTHN"
	IdentifierYubiMfa         = "YUBICO TOKEN:HARDWARE"
)

var logger = logrus.WithField("provider", "okta")

var (
	supportedMfaOptions = map[string]string{
		IdentifierDuoMfa:          "DUO MFA authentication",
		IdentifierSmsMfa:          "SMS MFA authentication",
		IdentifierPushMfa:         "PUSH MFA authentication",
		IdentifierTotpMfa:         "TOTP MFA authentication",
		IdentifierOktaTotpMfa:     "Okta MFA authentication",
		IdentifierSymantecTotpMfa: "Symantec VIP MFA authentication",
		IdentifierFIDOWebAuthn:    "FIDO WebAuthn MFA authentication",
		IdentifierYubiMfa:         "YUBICO TOKEN:HARDWARE",
	}
)

// Client is a wrapper representing a Okta SAML client
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
	mfa    string
}

// AuthRequest represents an mfa okta request
type AuthRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	StateToken string `json:"stateToken,omitempty"`
}

// VerifyRequest represents an mfa verify request
type VerifyRequest struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode,omitempty"`
}

// mfaChallengeContext is used to hold MFA challenge context in a simple struct.
type mfaChallengeContext struct {
	factorID              string
	oktaVerify            string
	mfaIdentifer          string
	challengeResponseBody string
}

// New creates a new Okta client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// assign a response validator to ensure all responses are either success or a redirect
	// this is to avoid have explicit checks for every single response
	client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	// add cookie jar to keep track of cookies during okta login flow
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, errors.Wrap(err, "error building cookie jar")
	}
	client.Jar = jar

	return &Client{
		client: client,
		mfa:    idpAccount.MFA,
	}, nil
}

type ctxKey string

// Authenticate logs into Okta and returns a SAML response
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error building oktaURL")
	}

	oktaOrgHost := oktaURL.Host

	//dummy request to set device token cookie ("dt")
	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building device token request")
	}
	_, err = oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving device token")
	}

	//authenticate via okta api
	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password}
	if loginDetails.StateToken != "" {
		authReq = AuthRequest{StateToken: loginDetails.StateToken}
	}
	authBody := new(bytes.Buffer)
	err = json.NewEncoder(authBody).Encode(authReq)
	if err != nil {
		return "", errors.Wrap(err, "error encoding authreq")
	}

	authSubmitURL := fmt.Sprintf("https://%s/api/v1/authn", oktaOrgHost)

	req, err = http.NewRequest("POST", authSubmitURL, authBody)
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving auth response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

	authStatus := gjson.Get(resp, "status").String()
	oktaSessionToken := gjson.Get(resp, "sessionToken").String()

	// mfa required
	if authStatus == "MFA_REQUIRED" {
		oktaSessionToken, err = verifyMfa(oc, oktaOrgHost, loginDetails, resp)
		if err != nil {
			return "", errors.Wrap(err, "error verifying MFA")
		}
	}

	//now call saml endpoint
	oktaSessionRedirectURL := fmt.Sprintf("https://%s/login/sessionCookieRedirect", oktaOrgHost)

	req, err = http.NewRequest("GET", oktaSessionRedirectURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("checkAccountSetupComplete", "true")
	q.Add("token", oktaSessionToken)
	q.Add("redirectUrl", loginDetails.URL)
	req.URL.RawQuery = q.Encode()

	ctx := context.WithValue(context.Background(), ctxKey("login"), loginDetails)
	return oc.follow(ctx, req, loginDetails)
}

func (oc *Client) follow(ctx context.Context, req *http.Request, loginDetails *creds.LoginDetails) (string, error) {

	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error following")
	}
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	var handler func(context.Context, *goquery.Document) (context.Context, *http.Request, error)

	if docIsFormRedirectToAWS(doc) {
		logger.WithField("type", "saml-response-to-aws").Debug("doc detect")
		if samlResponse, ok := extractSAMLResponse(doc); ok {
			decodedSamlResponse, err := base64.StdEncoding.DecodeString(samlResponse)
			if err != nil {
				return "", errors.Wrap(err, "failed to decode saml-response")
			}
			logger.WithField("type", "saml-response").WithField("saml-response", string(decodedSamlResponse)).Debug("doc detect")
			return samlResponse, nil
		}
	} else if docIsFormSamlRequest(doc) {
		logger.WithField("type", "saml-request").Debug("doc detect")
		handler = oc.handleFormRedirect
	} else if docIsFormResume(doc) {
		logger.WithField("type", "resume").Debug("doc detect")
		handler = oc.handleFormRedirect
	} else if docIsFormSamlResponse(doc) {
		logger.WithField("type", "saml-response").Debug("doc detect")
		handler = oc.handleFormRedirect
	} else {
		req, err = http.NewRequest("GET", loginDetails.URL, nil)
		if err != nil {
			return "", errors.Wrap(err, "error building app request")
		}
		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving app response")
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}
		stateToken, err := getStateTokenFromOktaPageBody(string(body))
		if err != nil {
			return "", errors.Wrap(err, "error retrieving saml response")
		}
		loginDetails.StateToken = stateToken
		return oc.Authenticate(loginDetails)
	}

	if handler == nil {
		html, _ := doc.Selection.Html()
		logger.WithField("doc", html).Debug("Unknown document type")
		return "", fmt.Errorf("Unknown document type")
	}

	ctx, req, err = handler(ctx, doc)
	if err != nil {
		return "", err
	}
	return oc.follow(ctx, req, loginDetails)

}

func getStateTokenFromOktaPageBody(responseBody string) (string, error) {
	re := regexp.MustCompile("var stateToken = '(.*)';")
	match := re.FindStringSubmatch(responseBody)
	if len(match) < 2 {
		return "", errors.New("cannot find state token")
	}
	return strings.Replace(match[1], `\x2D`, "-", -1), nil
}

func parseMfaIdentifer(json string, arrayPosition int) string {
	mfaProvider := gjson.Get(json, fmt.Sprintf("_embedded.factors.%d.provider", arrayPosition)).String()
	factorType := strings.ToUpper(gjson.Get(json, fmt.Sprintf("_embedded.factors.%d.factorType", arrayPosition)).String())
	return fmt.Sprintf("%s %s", mfaProvider, factorType)
}

func (oc *Client) handleFormRedirect(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting redirect form")
	}
	req, err := form.BuildRequest()
	return ctx, req, err
}

func docIsFormSamlRequest(doc *goquery.Document) bool {
	return doc.Find("input[name=\"SAMLRequest\"]").Size() == 1
}

func docIsFormSamlResponse(doc *goquery.Document) bool {
	return doc.Find("input[name=\"SAMLResponse\"]").Size() == 1
}

func docIsFormResume(doc *goquery.Document) bool {
	return doc.Find("input[name=\"RelayState\"]").Size() == 1
}

func docIsFormRedirectToAWS(doc *goquery.Document) bool {
	urls := []string{"form[action=\"https://signin.aws.amazon.com/saml\"]",
		"form[action=\"https://signin.amazonaws-us-gov.com/saml\"]",
		"form[action=\"https://signin.amazonaws.cn/saml\"]",
	}

	for _, value := range urls {
		if doc.Find(value).Size() > 0 {
			return true
		}
	}
	return false
}

func extractSAMLResponse(doc *goquery.Document) (v string, ok bool) {
	return doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
}

func findMfaOption(mfa string, mfaOptions []string, startAtIdx int) int {
	for idx, val := range mfaOptions {
		if startAtIdx > idx {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(val), mfa) {
			return idx
		}
	}
	return 0
}

func getMfaChallengeContext(oc *Client, mfaOption int, resp string) (*mfaChallengeContext, error) {
	stateToken := gjson.Get(resp, "stateToken").String()
	factorID := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d.id", mfaOption)).String()
	oktaVerify := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d._links.verify.href", mfaOption)).String()
	mfaIdentifer := parseMfaIdentifer(resp, mfaOption)

	logger.WithField("factorID", factorID).WithField("oktaVerify", oktaVerify).WithField("mfaIdentifer", mfaIdentifer).Debug("MFA")

	if _, ok := supportedMfaOptions[mfaIdentifer]; !ok {
		return nil, errors.New("unsupported mfa provider")
	}

	// get signature & callback
	verifyReq := VerifyRequest{StateToken: stateToken}
	verifyBody := new(bytes.Buffer)

	// Login flow is different for YubiKeys ( of course )
	// https://developer.okta.com/docs/reference/api/factors/#request-example-for-verify-yubikey-factor
	// verifyBody needs to be a json document with the OTP from the yubikey in it.
	// yay
	switch mfa := mfaIdentifer; mfa {
	case IdentifierYubiMfa:
		verifyCode := prompter.Password("Press the button on your yubikey")
		verifyReq.PassCode = verifyCode
	}

	err := json.NewEncoder(verifyBody).Encode(verifyReq)
	if err != nil {
		return nil, errors.Wrap(err, "error encoding verifyReq")
	}

	req, err := http.NewRequest("POST", oktaVerify, verifyBody)
	if err != nil {
		return nil, errors.Wrap(err, "error building verify request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving verify response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body from response")
	}

	return &mfaChallengeContext{
		factorID:              factorID,
		oktaVerify:            oktaVerify,
		mfaIdentifer:          mfaIdentifer,
		challengeResponseBody: string(body),
	}, nil
}

func verifyMfa(oc *Client, oktaOrgHost string, loginDetails *creds.LoginDetails, resp string) (string, error) {
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

	if strings.ToUpper(oc.mfa) != "AUTO" {
		mfaOption = findMfaOption(oc.mfa, mfaOptions, 0)
	} else if len(mfaOptions) > 1 {
		mfaOption = prompter.Choose("Select which MFA option to use", mfaOptions)
	}

	challengeContext, err := getMfaChallengeContext(oc, mfaOption, resp)
	if err != nil {
		return "", err
	}

	switch mfa := challengeContext.mfaIdentifer; mfa {
	case IdentifierYubiMfa:
		return gjson.Get(challengeContext.challengeResponseBody, "sessionToken").String(), nil
	case IdentifierSmsMfa, IdentifierTotpMfa, IdentifierOktaTotpMfa, IdentifierSymantecTotpMfa:
		var verifyCode = loginDetails.MFAToken
		if verifyCode == "" {
			verifyCode = prompter.StringRequired("Enter verification code")
		}
		tokenReq := VerifyRequest{StateToken: stateToken, PassCode: verifyCode}
		tokenBody := new(bytes.Buffer)
		err = json.NewEncoder(tokenBody).Encode(tokenReq)
		if err != nil {
			return "", errors.Wrap(err, "error encoding token data")
		}

		req, err := http.NewRequest("POST", challengeContext.oktaVerify, tokenBody)
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
		body := challengeContext.challengeResponseBody
		for {
			// on 'success' status
			if gjson.Get(body, "status").String() == "SUCCESS" {
				fmt.Printf(" Approved\n\n")
				return gjson.Get(body, "sessionToken").String(), nil
			}

			// otherwise probably still waiting
			switch gjson.Get(body, "factorResult").String() {

			case "WAITING":
				time.Sleep(3 * time.Second)
				fmt.Printf(".")
				logger.Debug("Waiting for user to authorize login")
				updatedContext, err := getMfaChallengeContext(oc, mfaOption, resp)
				if err != nil {
					return "", err
				}
				body = updatedContext.challengeResponseBody

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
		duoHost := gjson.Get(challengeContext.challengeResponseBody, "_embedded.factor._embedded.verification.host").String()
		duoSignature := gjson.Get(challengeContext.challengeResponseBody, "_embedded.factor._embedded.verification.signature").String()
		duoSiguatres := strings.Split(duoSignature, ":")
		//duoSignatures[0] = TX
		//duoSignatures[1] = APP
		duoCallback := gjson.Get(challengeContext.challengeResponseBody, "_embedded.factor._embedded.verification._links.complete.href").String()

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

		req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}
		q := req.URL.Query()
		q.Add("tx", duoSiguatres[0])
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		//try to extract sid
		doc, err := goquery.NewDocumentFromReader(res.Body)
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

		resp = string(body)

		duoTxStat := gjson.Get(resp, "stat").String()
		duoTxID := gjson.Get(resp, "response.txid").String()
		if duoTxStat != "OK" {
			return "", errors.New("error authenticating mfa device")
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
		newSID := gjson.Get(resp, "response.sid").String()
		if newSID != "" {
			duoSID = newSID
		}

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
				newSID = gjson.Get(resp, "response.sid").String()
				if newSID != "" {
					duoSID = newSID
				}

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

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)

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

		resp := string(body)

		duoTxStat = gjson.Get(resp, "stat").String()
		if duoTxStat != "OK" {
			message := gjson.Get(resp, "message").String()
			return "", fmt.Errorf("duoResultSubmit: %s %s", duoTxStat, message)
		}

		duoTxCookie := gjson.Get(resp, "response.cookie").String()
		if duoTxCookie == "" {
			return "", errors.New("duoResultSubmit: Unable to get response.cookie")
		}

		// callback to okta with cookie
		oktaForm := url.Values{}
		oktaForm.Add("id", challengeContext.factorID)
		oktaForm.Add("stateToken", stateToken)
		oktaForm.Add("sig_response", fmt.Sprintf("%s:%s", duoTxCookie, duoSiguatres[1]))

		req, err = http.NewRequest("POST", duoCallback, strings.NewReader(oktaForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		_, err = oc.client.Do(req) // TODO: check result
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		// extract okta session token

		verifyReq := VerifyRequest{StateToken: stateToken}
		verifyBody := new(bytes.Buffer)
		err = json.NewEncoder(verifyBody).Encode(verifyReq)
		if err != nil {
			return "", errors.Wrap(err, "error encoding verify request")
		}

		req, err = http.NewRequest("POST", challengeContext.oktaVerify, verifyBody)
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

		return gjson.GetBytes(body, "sessionToken").String(), nil

	case IdentifierFIDOWebAuthn:
		return fidoWebAuthn(oc, oktaOrgHost, challengeContext, mfaOption, stateToken, mfaOptions, resp)
	}

	// catch all
	return "", errors.New("no mfa options provided")
}

func fidoWebAuthn(oc *Client, oktaOrgHost string, challengeContext *mfaChallengeContext, mfaOption int, stateToken string, mfaOptions []string, resp string) (string, error) {

	var signedAssertion *SignedAssertion
	challengeResponseBody := challengeContext.challengeResponseBody
	lastMfaOption := mfaOption

	for {
		nonce := gjson.Get(challengeResponseBody, "_embedded.factor._embedded.challenge.challenge").String()
		credentialID := gjson.Get(challengeResponseBody, "_embedded.factor.profile.credentialId").String()
		version := gjson.Get(challengeResponseBody, "_embedded.factor.profile.version").String()

		fidoClient, err := NewFidoClient(
			nonce,
			oktaOrgHost,
			version,
			credentialID,
			stateToken,
			new(U2FDeviceFinder),
		)
		if err != nil {
			return "", err
		}

		signedAssertion, err = fidoClient.ChallengeU2F()
		if err != nil {
			// if this error is not a bad key error we are done
			if _, ok := err.(*u2fhost.BadKeyHandleError); !ok {
				return "", errors.Wrap(err, "failed to perform U2F challenge")
			}

			// check if there is another fido device and try that
			nextMfaOption := findMfaOption(oc.mfa, mfaOptions, lastMfaOption)
			if nextMfaOption <= lastMfaOption {
				return "", errors.Wrap(err, "tried all MFA options")
			}
			lastMfaOption = nextMfaOption

			nextChallengeContext, err := getMfaChallengeContext(oc, nextMfaOption, resp)
			if err != nil {
				return "", errors.Wrap(err, "get mfa challenge failed for U2F device")
			}
			challengeResponseBody = nextChallengeContext.challengeResponseBody
			continue
		}

		break
	}

	payload, err := json.Marshal(signedAssertion)
	if err != nil {
		return "", err
	}

	webauthnCallback := gjson.Get(challengeResponseBody, "_links.next.href").String()
	req, err := http.NewRequest("POST", webauthnCallback, strings.NewReader(string(payload)))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving verify response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}

	return gjson.GetBytes(body, "sessionToken").String(), nil
}
