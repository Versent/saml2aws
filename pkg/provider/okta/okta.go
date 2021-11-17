package okta

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/marshallbrekka/go-u2fhost"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/helper/credentials"
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

	client          *provider.HTTPClient
	mfa             string
	targetURL       string
	disableSessions bool
	rememberDevice  bool
}

// AuthRequest represents an mfa okta request
type AuthRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	StateToken string `json:"stateToken,omitempty"`
}

// VerifyRequest represents an mfa verify request
type VerifyRequest struct {
	StateToken     string `json:"stateToken"`
	PassCode       string `json:"passCode,omitempty"`
	RememberDevice string `json:"rememberDevice,omitempty"` // This is needed to remember Okta MFA device
}

// Articles referencing the Okta MFA + remembering device
// https://developer.okta.com/docs/reference/api/authn/#verify-security-question-factor
// https://devforum.okta.com/t/how-per-device-remember-me-api-works/3955/3

// SessionRequst holds the SessionToken used to create an Okta Session
type SessionRequst struct {
	SessionToken string `json:"sessionToken"`
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

	disableSessions := idpAccount.DisableSessions
	rememberDevice := !idpAccount.DisableRememberDevice

	if idpAccount.DisableSessions { // if user disabled sessions, also dont remember device
		rememberDevice = false
	}

	// Debug the disableSessions and rememberDevice values
	logger.Debugf("okta | disableSessions: %v", disableSessions)
	logger.Debugf("okta | rememberDevice: %v", rememberDevice)

	return &Client{
		client:          client,
		mfa:             idpAccount.MFA,
		targetURL:       idpAccount.TargetURL,
		disableSessions: disableSessions,
		rememberDevice:  rememberDevice,
	}, nil
}

type ctxKey string

// createSession calls the Okta sessions API to create a new session using the sessionToken passed in
func (oc *Client) createSession(loginDetails *creds.LoginDetails, sessionToken string) (string, string, error) {
	logger.Debug("create session func called")
	if loginDetails == nil || sessionToken == "" {
		logger.Debugf("unable to create an Okta session, nil input | loginDetails: %v | sessionToken: %s", loginDetails, sessionToken)
		return "", "", fmt.Errorf("unable to create an okta session, nil input")
	}

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return "", "", errors.Wrap(err, "error building okta url")
	}

	oktaOrgHost := oktaURL.Host

	//authenticate via okta api
	sessionReq := SessionRequst{SessionToken: sessionToken}
	sessionReqBody := new(bytes.Buffer)
	err = json.NewEncoder(sessionReqBody).Encode(sessionReq)
	if err != nil {
		return "", "", errors.Wrap(err, "error encoding session req")
	}

	sessionReqURL := fmt.Sprintf("https://%s/api/v1/sessions", oktaOrgHost)

	req, err := http.NewRequest("POST", sessionReqURL, sessionReqBody)
	if err != nil {
		return "", "", errors.Wrap(err, "error building new session request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", "", errors.Wrap(err, "error retrieving session response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", errors.Wrap(err, "error retrieving body from response")
	}

	if res.StatusCode != 200 { // https://developer.okta.com/docs/reference/api/sessions/#response-parameters
		if res.StatusCode == 401 {
			return "", "", fmt.Errorf("unable to create an Okta session, invalid sessionToken")
		}
		return "", "", fmt.Errorf("unable to create an Okta session, HTTP Code: %d", res.StatusCode)
	}

	resp := string(body)

	oktaSessionExpiresAtStr := gjson.Get(resp, "expiresAt").String()
	logger.Debugf("okta session expires at: %s", oktaSessionExpiresAtStr)

	oktaSessionCookie := gjson.Get(resp, "id").String()

	err = credentials.SaveCredentials(loginDetails.URL+"/sessionCookie", loginDetails.Username, oktaSessionCookie)
	if err != nil {
		return "", "", fmt.Errorf("error storing okta session token | err: %v", err)
	}

	oktaSessionToken := gjson.Get(resp, "sessionToken").String()
	sessionResponseStatus := gjson.Get(resp, "status").String()
	switch sessionResponseStatus {
	case "ACTIVE":
		logger.Debug("okta session established")
	case "MFA_REQUIRED":
		oktaSessionToken, err = verifyMfa(oc, oktaOrgHost, loginDetails, resp)
		if err != nil {
			return "", "", errors.Wrap(err, "error verifying MFA")
		}
	case "MFA_ENROLL":
		// Not yet fully implemented, most likely no need, so just return the status as the error string...
		return "", "", fmt.Errorf("MFA_ENROLL")
	}

	return oktaSessionCookie, oktaSessionToken, nil
}

// validateSession calls the Okta session API to check if the session is valid
// returns an error if the session is NOT valid
func (oc *Client) validateSession(loginDetails *creds.LoginDetails) error {
	logger.Debug("validate session func called")

	if loginDetails == nil {
		logger.Debug("unable to validate the okta session, nil input")
		return fmt.Errorf("unable to validate the okta session, nil input")
	}

	sessionCookie := loginDetails.OktaSessionCookie

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return errors.Wrap(err, "error building oktaURL")
	}

	oktaOrgHost := oktaURL.Host

	sessionReqURL := fmt.Sprintf("https://%s/api/v1/sessions/me", oktaOrgHost) // This api endpoint returns user details
	sessionReqBody := new(bytes.Buffer)

	req, err := http.NewRequest("GET", sessionReqURL, sessionReqBody)
	if err != nil {
		return errors.Wrap(err, "error building new session request")
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Cookie", fmt.Sprintf("sid=%s", sessionCookie))

	res, err := oc.client.Do(req)
	if err != nil {
		return errors.Wrap(err, "error retrieving session response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

	if res.StatusCode != 200 {
		logger.Debug("invalid okta session")
		return fmt.Errorf("invalid okta session")
	} else {
		sessionResponseStatus := gjson.Get(resp, "status").String()
		switch sessionResponseStatus {
		case "ACTIVE":
			logger.Debug("okta session established")
		case "MFA_REQUIRED":
			_, err := verifyMfa(oc, oktaOrgHost, loginDetails, resp)
			if err != nil {
				return errors.Wrap(err, "error verifying MFA")
			}
		case "MFA_ENROLL":
			// Not yet fully implemented, so just return the status as the error string...
			return fmt.Errorf("MFA_ENROLL")
		}
	}

	logger.Debug("valid okta session")
	return nil
}

// authWithSession authenticates user via sessions API -> direct to target URL using follow func
func (oc *Client) authWithSession(loginDetails *creds.LoginDetails) (string, error) {
	logger.Debug("auth with session func called")
	sessionCookie := loginDetails.OktaSessionCookie
	err := oc.validateSession(loginDetails)
	if err != nil {
		modifiedLoginDetails := loginDetails
		modifiedLoginDetails.OktaSessionCookie = ""
		return oc.Authenticate(modifiedLoginDetails)
	}

	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building authWithSession request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Cookie", fmt.Sprintf("sid=%s", sessionCookie))

	ctx := context.WithValue(context.Background(), ctxKey("authWithSession"), loginDetails)

	res, err := oc.client.Do(req)
	if err != nil {
		logger.Debugf("error authing with session: %v", err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logger.Debugf("error reading body for auth with session: %v", err)
	}

	// This usually happens if using an active session (> 5 mins) but MFA was NOT remembered
	if strings.Contains(string(body), "/login/step-up/") { // https://developer.okta.com/docs/reference/api/authn/#step-up-authentication-with-okta-session
		logger.Debug("okta step-up prompted, need mfa...")
		stateToken, err := getStateTokenFromOktaPageBody(string(body))
		if err != nil {
			return "", errors.Wrap(err, "error retrieving saml response")
		}
		loginDetails.StateToken = stateToken
		return oc.Authenticate(loginDetails)
	}

	return oc.follow(ctx, req, loginDetails)
}

// getDeviceTokenFromOkta creates a dummy HTTP call to Okta and returns the device token
// cookie value
// This function is not currently used and but can be used in the future
func (oc *Client) getDeviceTokenFromOkta(loginDetails *creds.LoginDetails) (string, error) {
	//dummy request to set device token cookie ("dt")
	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building device token request")
	}
	resp, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving device token")
	}

	for _, c := range resp.Cookies() {
		if c.Name == "DT" { // Device token
			return c.Value, nil
		}
	}

	return "", fmt.Errorf("unable to get a device token from okta")
}

// setDeviceTokenCookie sets the DT cookie in the HTTP Client cookie jar
// using the okta_<loginDetails.Username>_saml2aws, we reduce making an extra api call
// this func can be uplifted in the future to set custom device tokens or used with
// getDeviceTokenFromOkta function
func (oc *Client) setDeviceTokenCookie(loginDetails *creds.LoginDetails) error {

	// getDeviceTokenFromOkta is not used but doing this to keep the function code
	// uncommented (avoid linting issues)
	if false {
		dt, _ := oc.getDeviceTokenFromOkta(loginDetails)
		logger.Debugf("getDeviceTokenFromOkta is not yet implemented: dt: %s", dt)
	}

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return errors.Wrap(err, "error building oktaURL to set device token cookie")
	}
	oktaURLScheme := oktaURL.Scheme
	oktaURLHost := oktaURL.Host
	baseURL := &url.URL{Scheme: oktaURLScheme, Host: oktaURLHost, Path: "/"}

	var cookies []*http.Cookie
	cookie := http.Cookie{
		Name:    "DT",
		Secure:  true,
		Expires: time.Now().Add(time.Hour * 24 * 30),                    // 30 Days -> this time might not matter as this cookie is set on every saml2aws login request
		Value:   fmt.Sprintf("okta_%s_saml2aws", loginDetails.Username), // Okta recommends using an UUID but this should be unique enough. Also, this is key to remembering Okta MFA device
	}
	cookies = append(cookies, &cookie)
	oc.client.Jar.SetCookies(baseURL, cookies)

	return nil
}

// primaryAuth creates the Okta Primary Authentication request
// returns the authStatus, sessionToken, http response and a error
func (oc *Client) primaryAuth(loginDetails *creds.LoginDetails) (string, string, string, error) {

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return "", "", "", errors.Wrap(err, "error building oktaURL")
	}

	oktaOrgHost := oktaURL.Host
	//authenticate via okta api
	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password}
	if loginDetails.StateToken != "" {
		authReq = AuthRequest{StateToken: loginDetails.StateToken}
	}
	authBody := new(bytes.Buffer)
	err = json.NewEncoder(authBody).Encode(authReq)
	if err != nil {
		return "", "", "", errors.Wrap(err, "error encoding authreq")
	}

	authSubmitURL := fmt.Sprintf("https://%s/api/v1/authn", oktaOrgHost)

	req, err := http.NewRequest("POST", authSubmitURL, authBody)
	if err != nil {
		return "", "", "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", "", "", errors.Wrap(err, "error retrieving auth response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", "", errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

	authStatus := gjson.Get(resp, "status").String()
	oktaSessionToken := gjson.Get(resp, "sessionToken").String()

	return authStatus, oktaSessionToken, resp, nil
}

// Authenticate logs into Okta and returns a SAML response
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	// Set Okta device token
	err := oc.setDeviceTokenCookie(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error setting device token in cookie jar")
	}

	// Get Okta session cookie (sid) from login details (if found via login.go)
	oktaSessionCookie := loginDetails.OktaSessionCookie

	// If user disabled sessions, do not use sessions API
	if !oc.disableSessions {
		// If Okta session cookie is not empty
		// Note on checking StateToken: StateToken is set in the follow func
		// if the follow func calls this function (Authenticate), it means the session requires MFA to continue
		// so don't call authWithSession, instead flow through to create the primary authentication call
		if oktaSessionCookie != "" && loginDetails.StateToken == "" {
			return oc.authWithSession(loginDetails)
		}
	}

	oktaURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error building oktaURL")
	}

	oktaOrgHost := oktaURL.Host

	authStatus, oktaSessionToken, primaryAuthResp, err := oc.primaryAuth(loginDetails)
	if err != nil {
		return "", err
	}

	// mfa required
	if authStatus == "MFA_REQUIRED" {
		oktaSessionToken, err = verifyMfa(oc, oktaOrgHost, loginDetails, primaryAuthResp)
		if err != nil {
			return "", errors.Wrap(err, "error verifying MFA")
		}
	}

	// if user disabled sessions, default to using standard login WITHOUT sessions
	if oc.disableSessions {
		//now call saml endpoint
		oktaSessionRedirectURL := fmt.Sprintf("https://%s/login/sessionCookieRedirect", oktaOrgHost)

		req, err := http.NewRequest("GET", oktaSessionRedirectURL, nil)
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

	// Only reaches here if user DID NOT DISABLE okta sessions
	if oktaSessionCookie == "" {
		oktaSessionCookie, _, err = oc.createSession(loginDetails, oktaSessionToken)
		if err != nil {
			return "", err
		}
		loginDetails.OktaSessionCookie = oktaSessionCookie
	}

	return oc.authWithSession(loginDetails)
}

func (oc *Client) follow(ctx context.Context, req *http.Request, loginDetails *creds.LoginDetails) (string, error) {
	if ctx.Value(ctxKey("follow")) != nil {
		logger.Debug("follow func called from itself")
	}

	if ctx.Value(ctxKey("authWithSession")) != nil {
		logger.Debug("follow func called from auth with session func")
	}

	res, err := oc.client.Do(req)
	if err != nil {
		logger.Debug("ERROR FOLLOWING")
		return "", errors.Wrap(err, "error following")
	}
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		logger.Debug("FAILED TO BUILD DOC FROM RESP")
		return "", errors.Wrap(err, "failed to build document from response")
	}

	var handler func(context.Context, *goquery.Document) (context.Context, *http.Request, error)

	if docIsFormRedirectToTarget(doc, oc.targetURL) {
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

func docIsFormRedirectToTarget(doc *goquery.Document, target string) bool {
	var urls []string
	if target != "" {
		url := fmt.Sprintf("form[action=\"%s\"]", target)
		urls = []string{url}
	} else {
		urls = []string{"form[action=\"https://signin.aws.amazon.com/saml\"]",
			"form[action=\"https://signin.amazonaws-us-gov.com/saml\"]",
			"form[action=\"https://signin.amazonaws.cn/saml\"]",
		}
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
	verifyReq := VerifyRequest{StateToken: stateToken, RememberDevice: strconv.FormatBool(oc.rememberDevice)}
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
		tokenReq := VerifyRequest{StateToken: stateToken, PassCode: verifyCode, RememberDevice: strconv.FormatBool(oc.rememberDevice)}
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

		log.Println("Waiting for approval, please check your Okta Verify app ...")

		// loop until success, error, or timeout
		body := challengeContext.challengeResponseBody
		for {
			// on 'success' status
			if gjson.Get(body, "status").String() == "SUCCESS" {
				log.Println(" Approved")
				logger.Debugf("func verifyMfa | okta exiry: %s", gjson.Get(body, "expiresAt").String()) // DEBUG
				return gjson.Get(body, "sessionToken").String(), nil
			}

			// otherwise probably still waiting
			switch gjson.Get(body, "factorResult").String() {

			case "WAITING":
				time.Sleep(3 * time.Second)
				logger.Debug("Waiting for user to authorize login")
				updatedContext, err := getMfaChallengeContext(oc, mfaOption, resp)
				if err != nil {
					return "", err
				}
				body = updatedContext.challengeResponseBody

			case "TIMEOUT":
				log.Println(" Timeout")
				return "", errors.New("User did not accept MFA in time")

			case "REJECTED":
				log.Println(" Rejected")
				return "", errors.New("MFA rejected by user")

			default:
				log.Println(" Error")
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
		duoForm.Add("flash_version", "")
		duoForm.Add("screen_resolution_width", "3008")
		duoForm.Add("screen_resolution_height", "1692")
		duoForm.Add("color_depth", "24")
		duoForm.Add("is_cef_browser", "false")
		duoForm.Add("is_ipad_os", "false")
		duoForm.Add("is_ie_compatability_mode", "")
		duoForm.Add("acting_ie_version", "")
		duoForm.Add("react_support", "true")
		duoForm.Add("react_support_error_message", "")
		duoForm.Add("tx", duoSiguatres[0])

		req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		q := req.URL.Query()
		q.Add("tx", duoSiguatres[0])
		q.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", oktaOrgHost))
		q.Add("v", "2.8")
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		defer res.Body.Close()

		//try to extract sid
		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error parsing document")
		}

		if doc.Find("form[id=\"client_cert_form\"]").Length() > 0 {
			// If you enable DUO trusted cert validation, it requires an extra step before continuing.
			// The way the validation process works is it attempts to send a request to a localhost:15310
			// where the DUO cert proxy may be running.  This returns a JSON blob if it was successful.
			// If that isn't running, there is also a public DUO endpoint you can use for the validation.
			// This code attempts to hit the local validator, then the remote one if it is not available,
			// which is the same flow the webpage does if you validate through a browser.

			// We then follow up again with a POST request to /frame/web/v1/auth, this time with the
			// cert validation parameters in the POST body.  If that succeeds, then we can continue
			// along the existing request path.

			sid, _ := doc.Find("input[name=\"sid\"]").Attr("value")
			certUrl, _ := doc.Find("input[name=\"certs_url\"]").Attr("value")
			txid, _ := doc.Find("input[name=\"certs_txid\"]").Attr("value")
			certifierUrl, _ := doc.Find("input[name=\"certifier_url\"]").Attr("value")

			duoUrl := fmt.Sprintf("%s?type=AJAX&sid=%s&certs_txid=%s", certUrl, url.QueryEscape(sid), txid)
			duoCertifierURL := fmt.Sprintf("%s?certUrl=%s", certifierUrl, url.QueryEscape(duoUrl))

			// The locally running certifier does not have a valid certificate, so we have to skip verification
			customTransport := http.DefaultTransport.(*http.Transport).Clone()
			customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			originalTransport := oc.client.Transport

			oc.client.Transport = customTransport

			req, err = http.NewRequest("GET", duoCertifierURL, nil)

			if err != nil {
				return "", errors.Wrap(err, "error building cert validation request")
			}

			req.Header.Add("Referer", "https://"+duoHost)
			res, err = oc.client.Do(req)
			oc.client.Transport = originalTransport

			if err != nil {
				// Local certifier not running, try online one
				duoCertURL := fmt.Sprintf("%s?sid=%s&certs_txid=%s&type=AJAX", certUrl, url.QueryEscape(sid), txid)

				req, err = http.NewRequest("GET", duoCertURL, nil)

				if err != nil {
					return "", errors.Wrap(err, "error building cert validation request ")
				}

				req.Header.Add("Referer", "https://"+duoHost)
				res, err = oc.client.Do(req)

				if err != nil {
					return "", errors.Wrap(err, "error retrieving cert validation response")
				}
			}

			defer res.Body.Close()

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving body from response")
			}

			resp = string(body)

			duoStat := gjson.Get(resp, "stat").String()
			if duoStat != "OK" {
				return "", errors.Wrap(err, "error validation certificate")
			}

			certForm := url.Values{}
			certForm.Add("sid", sid)
			certForm.Add("certs_url", certUrl)
			certForm.Add("certs_txid", txid)
			certForm.Add("certifier_url", certifierUrl)

			// Try POST again
			req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(certForm.Encode()))
			if err != nil {
				return "", errors.Wrap(err, "error building authentication request")
			}
			req.URL.RawQuery = q.Encode()

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			res, err = oc.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving verify response")
			}
			defer res.Body.Close()

			doc, err = goquery.NewDocumentFromResponse(res)
			if err != nil {
				return "", errors.Wrap(err, "error parsing document")
			}

		} else if doc.Find("form[id=\"endpoint-health-form\"]").Length() > 0 {
			origUrl := req.URL.String()

			txid, _ := doc.Find("input[name=\"txid\"]").Attr("value")
			sid, _ := doc.Find("input[name=\"sid\"]").Attr("value")
			ehServiceUrl, _ := doc.Find("input[name=\"eh_service_url\"]").Attr("value")
			akey, _ := doc.Find("input[name=\"akey\"]").Attr("value")
			responseTimeout, _ := doc.Find("input[name=\"response_timeout\"]").Attr("value")
			parent, _ := doc.Find("input[name=\"parent\"]").Attr("value")
			duoAppUrl, _ := doc.Find("input[name=\"duo_app_url\"]").Attr("value")
			ehDownloadLink, _ := doc.Find("input[name=\"eh_download_link\"]").Attr("value")
			isSilentCollection, _ := doc.Find("input[name=\"is_silent_collection\"]").Attr("value")

			timestamp := strconv.Itoa((int)(time.Now().Unix()))
			duoAliveUrl := "https://127.0.0.1:53100/alive"
			req, _ := http.NewRequest("GET", duoAliveUrl, nil)

			q := req.URL.Query()
			q.Add("_", timestamp+"100")

			req.URL.RawQuery = q.Encode()
			req.Header.Add("Referer", "https://"+duoHost+"/")
			req.Header.Add("Origin", "https://"+duoHost)

			res, err = oc.client.Do(req)

			duoCheckEndpointAppURL := fmt.Sprintf("https://%s/frame/check_endpoint_app_status", duoHost)
			req, _ = http.NewRequest("GET", duoCheckEndpointAppURL, nil)

			q = req.URL.Query()

			q.Add("txid", txid)
			q.Add("sid", sid)

			req.URL.RawQuery = q.Encode()

			req.Header.Add("Referer", origUrl)
			req.Header.Add("X-Requested-With", "XMLHttpRequest")

			var wg sync.WaitGroup
			wg.Add(1)

			// check_endpoint_app_status blocks until the healthurl report is queried, so we need to use goroutines.
			go func(r *http.Request) {
				res, _ := oc.client.Do(req)
				defer res.Body.Close()
				wg.Done()
			}(req)

			// Separator

			duoHealthURL := "https://127.0.0.1:53100/report"

			req2, _ := http.NewRequest("GET", duoHealthURL, nil)

			q = req2.URL.Query()

			q.Add("txid", txid)
			q.Add("eh_service_url", ehServiceUrl+"?_="+timestamp+"101")

			req2.URL.RawQuery = q.Encode()
			req2.Header.Add("Referer", "https://"+duoHost)
			req2.Header.Add("Origin", "https://"+duoHost)

			res, err = oc.client.Do(req2)
			defer res.Body.Close()

			// Wait for check_endpoint_app_status to block
			wg.Wait()

			// Try the call to /v1/frame/auth again

			certForm := url.Values{}
			certForm.Add("sid", sid)
			certForm.Add("txid", txid)
			certForm.Add("eh_service_url", ehServiceUrl)
			certForm.Add("akey", akey)
			certForm.Add("response_timeout", responseTimeout)
			certForm.Add("parent", parent)
			certForm.Add("duo_app_url", duoAppUrl)
			certForm.Add("eh_download_link", ehDownloadLink)
			certForm.Add("is_silent_collection", isSilentCollection)

			time.Sleep(2 * time.Second)

			// Try POST again
			req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(certForm.Encode()))
			if err != nil {
				return "", errors.Wrap(err, "error building authentication request")
			}
			q = req.URL.Query()
			q.Add("tx", duoSiguatres[0])
			q.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", oktaOrgHost))
			q.Add("v", "2.8")

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			req.URL.RawQuery = q.Encode()

			res, err = oc.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving verify response")
			}
			defer res.Body.Close()

			doc, err = goquery.NewDocumentFromResponse(res)
			if err != nil {
				return "", errors.Wrap(err, "error parsing document")
			}

		}

		duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
		if !ok {
			return "", errors.Wrap(err, "unable to locate saml response")
		}
		duoSID = html.UnescapeString(duoSID)

		var duoMfaOptions = []string{}
		var token string

		webauthnOption := doc.Find("option[name=\"webauthn\"]")

		if webauthnOption.Length() > 0 {
			token, _ = webauthnOption.Attr("value")
			duoMfaOptions = append(duoMfaOptions, "U2F Key")
		}

		if doc.Find("option[value=\"phone1\"]").Length() > 0 {
			duoMfaOptions = append(duoMfaOptions, "Duo Push")
		}

		if doc.Find("option[value=\"token\"]").Length() > 0 {
			duoMfaOptions = append(duoMfaOptions, "Passcode")
		}

		duoMfaOption := 0

		if loginDetails.DuoMFAOption == "Duo Push" {
			duoMfaOption = 1
		} else if loginDetails.DuoMFAOption == "Passcode" {
			duoMfaOption = 2
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
		duoForm.Add("out_of_date", "false")

		switch duoMfaOptions[duoMfaOption] {
		case "Passcode":
			duoForm.Add("passcode", token)
		case "Duo Push":
			duoForm.Add("device", "phone1")
			duoForm.Add("factor", "Duo Push")
		case "U2F Key":
			duoForm.Add("device", "u2f_token")
			duoForm.Add("factor", "U2F Token")
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

		defer res.Body.Close()

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

		// Do the webauthn
		duoRestStatusCode := gjson.Get(resp, "response.status_code").String()

		if duoRestStatusCode == "u2f_sent" {
			appId := gjson.Get(resp, "response.u2f_sign_request.0.appId").String()
			//appId := "api-23a9854b.duosecurity.com"
			version := gjson.Get(resp, "response.u2f_sign_request.0.version").String()
			challengeNonce := gjson.Get(resp, "response.u2f_sign_request.0.challenge").String()
			keyHandle := gjson.Get(resp, "response.u2f_sign_request.0.keyHandle").String()
			sessionId := gjson.Get(resp, "response.u2f_sign_request.0.sessionId").String()

			u2fClient, err := NewDUOU2FClient(challengeNonce, appId, version, keyHandle, sessionId, new(U2FDeviceFinder))

			if err != nil {
				return "", err
			}

			rd, err := u2fClient.ChallengeU2F()
			if err != nil {
				return "", err
			}

			payload, err := json.Marshal(rd)
			if err != nil {
				return "", err
			}

			duoForm = url.Values{}
			duoForm.Add("sid", duoSID)
			duoForm.Add("device", "u2f_token")
			duoForm.Add("factor", "u2f_finish")
			duoForm.Add("days_to_block", "None")
			duoForm.Add("out_of_date", "False")
			duoForm.Add("days_out_of_date", "0")
			duoForm.Add("response_data", string(payload))

			duoSubmitURL = fmt.Sprintf("https://%s/frame/prompt", duoHost)

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

			defer res.Body.Close()

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving body from response")
			}

			resp = string(body)

			duoTxResult = gjson.Get(resp, "response.result").String()
			duoResultURL = gjson.Get(resp, "response.result_url").String()
			newSID = gjson.Get(resp, "response.sid").String()
			if newSID != "" {
				duoSID = newSID
			}

		}

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

		resp = string(body)

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

		verifyReq := VerifyRequest{StateToken: stateToken, RememberDevice: strconv.FormatBool(oc.rememberDevice)}
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
