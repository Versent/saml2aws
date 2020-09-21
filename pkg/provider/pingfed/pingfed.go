package pingfed

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/page"
	"github.com/GESkunkworks/gossamer3/pkg/prompter"
	"github.com/GESkunkworks/gossamer3/pkg/provider"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var logger = logrus.WithField("provider", "pingfed")

// Client wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

type ctxKey string

var (
	cookies        = []*http.Cookie{}
	resp           *http.Response
	deviceSelected = false
	mfaAttempt     = 0
)

// New create a new PingFed client
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
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate: Authenticate to PingFed and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	loginUrl := fmt.Sprintf("%s/idp/startSSO.ping?PartnerSpId=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)
	req, err := http.NewRequest("GET", loginUrl, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building request")
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), loginDetails)
	return ac.follow(ctx, req)
}

// follow: Perform the request and determine how it should be handled
func (ac *Client) follow(ctx context.Context, req *http.Request) (string, error) {
	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error following")
	}

	// Save the response so it can be used in a child
	resp = res

	// Store cookies from the response
	for _, cookie := range res.Cookies() {
		found := false
		for i, item := range cookies {
			if item.Name == cookie.Name {
				found = true
				cookies[i] = cookie
				break
			}
		}

		if !found {
			cookies = append(cookies, cookie)
		}
	}

	// Create document from response body
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
		handler = ac.handleFormRedirect
	} else if docIsFormResume(doc) {
		logger.WithField("type", "resume").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsFormSamlResponse(doc) {
		logger.WithField("type", "saml-response").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsPreLogin(doc) {
		logger.WithField("type", "pre-login").Debug("doc detect")
		handler = ac.handlePreLogin
	} else if docIsLogin(doc) {
		logger.WithField("type", "login").Debug("doc detect")
		handler = ac.handleLogin
	} else if docIsToken(doc) {
		logger.WithField("type", "token").Debug("doc detect")
		handler = ac.handleToken
	} else if docIsChallenge(doc) {
		logger.WithField("type", "confirm-token").Debug("doc detect")
		handler = ac.handleChallenge
	} else if docIsSiteMinderLogin(doc) {
		logger.WithField("type", "siteminder-login").Debug("doc detect")
		handler = ac.handleSiteMinderLogin
	} else if docIsSelectDevice(doc) {
		logger.WithField("type", "select-device").Debug("doc detect")
		handler = ac.handleSelectDevice
	} else if docIsSecurityKeyAuth(doc) {
		logger.WithField("type", "security-key").Debug("doc detect")
		handler = ac.handleSecurityKeyLogin
	} else if docIsOTP(doc) {
		logger.WithField("type", "otp").Debug("doc detect")
		handler = ac.handleOTP
	} else if docIsMfaSpinner(doc) {
		logger.WithField("type", "mfa-spinner").Debug("doc detect")
		handler = ac.handleMfaSpinner
	} else if docIsSwipe(doc) {
		logger.WithField("type", "swipe").Debug("doc detect")
		handler = ac.handleSwipe
	} else if docIsPingAuth(doc) {
		logger.WithField("type", "ping-auth").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsFormRedirect(doc) {
		logger.WithField("type", "form-redirect").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsWebAuthn(doc) {
		logger.WithField("type", "webauthn").Debug("doc detect")
		handler = ac.handleWebAuthn
	} else if docIsError(doc) {
		logger.WithField("type", "error").Debug("doc detect")
		pingError := strings.TrimSpace(doc.Find("div.ping-error").Text())
		errorDetails := strings.TrimSpace(doc.Find("div#error-details-div").Text())
		return "", fmt.Errorf("%s\n%s", pingError, errorDetails)
	}

	if handler == nil {
		html, _ := doc.Selection.Html()
		logger.WithField("doc", html).Debug("Unknown document type")
		return "", fmt.Errorf("Unknown document type")
	}

	// Generate the request
	ctx, req, err = handler(ctx, doc)
	if err != nil {
		return "", err
	}

	// Add cookies to the request
	addCookies(req, cookies)

	return ac.follow(ctx, req)
}

func (ac *Client) handlePreLogin(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	form.Values.Set("subject", loginDetails.Username)
	form.URL = makeAbsoluteURL(form.URL, loginDetails.URL)

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleLogin(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	form.Values.Set("pf.username", loginDetails.Username)
	form.Values.Set("pf.pass", loginDetails.Password)
	form.URL = makeAbsoluteURL(form.URL, loginDetails.URL)

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleToken(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	token := prompter.Password("Enter Token Code")

	// Make sure a token value was provided
	if token == "" {
		return ctx, nil, errors.New("MFA token code not provided")
	}

	form.Values.Set("pf.pass", token)
	form.URL = makeAbsoluteURL(form.URL, loginDetails.URL)

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleChallenge(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	token := prompter.Password("Enter Next Token Code")

	// Make sure a token value was provided
	if token == "" {
		return ctx, nil, errors.New("Next token code value not provided")
	}

	form.Values.Set("pf.challengeResponse", token)
	form.Values.Set("pf.ok", "clicked")
	form.URL = makeAbsoluteURL(form.URL, loginDetails.URL)

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSiteMinderLogin(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form#signon")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	// Pull MFA token from command line if specified
	token := loginDetails.MFAToken

	// Request token
	if loginDetails.MFAToken == "" || mfaAttempt > 0 {
		token = prompter.Password("Enter PIN + Token Code / Passcode")
	}

	// Make sure a token value was provided
	if token == "" {
		return ctx, nil, errors.New("MFA token value not provided")
	}

	form.Values.Set("username", loginDetails.Username)
	form.Values.Set("PASSWORD", token)
	form.URL = resp.Request.URL.String()
	mfaAttempt += 1

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleOTP(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "#otp-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting OTP form")
	}

	// Check if this is a yubikey auth
	promptMessage := "Enter passcode"
	authType := doc.Find("div.content h1")
	if authType.Size() == 1 && strings.Contains(authType.Text(), "YubiKey") {
		promptMessage = "Touch button on your YubiKey"
	}

	// Pull MFA token from command line if specified
	otp := loginDetails.MFAToken

	// Request OTP
	if loginDetails.MFAToken == "" || mfaAttempt > 0 {
		otp = prompter.Password(promptMessage)
	}

	// Make sure a value was provided
	if otp == "" {
		return ctx, nil, errors.New("OTP value not provided")
	}

	form.Values.Set("otp", otp)
	mfaAttempt += 1

	// Add CSRF token from cookie
	for _, cookie := range cookies {
		if cookie.Name == ".csrf" {
			form.Values.Set("csrfToken", cookie.Value)
			break
		}
	}

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSecurityKeyLogin(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	// Intercept and request user to select a device if they have not already
	if loginDetails.MFAPrompt && !deviceSelected {
		return ctx, checkForDevices(), nil
	}

	form, err := page.NewFormFromDocument(doc, "#otp-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting OTP form")
	}

	// Get public key options set by the server
	publicKeyOptions := form.Values.Get("publicKeyCredentialRequestOptions")

	// Perform security auth
	authRes, err := securityKeyAuth(publicKeyOptions)
	if err != nil {
		return ctx, nil, err
	}
	logger.Debugf("Auth Response: %+v\n", authRes)

	// Set the otp and build the request
	form.Values.Set("otp", authRes)
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleMfaSpinner(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "#loginForm")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting swipe status form")
	}

	form.URL = makeAbsoluteURL(form.URL, loginDetails.URL)

	time.Sleep(500 * time.Millisecond)

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSelectDevice(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	var deviceNames []string
	var deviceIds []string

	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	// Find device names and ids
	doc.Find("ul.device-list > li.device[data-id]").Each(func(_ int, selection *goquery.Selection) {
		// Extract device id
		deviceId, ok := selection.Attr("data-id")
		if !ok {
			return
		}

		// Extract device name
		deviceName := strings.TrimSpace(selection.Find("a").Get(0).FirstChild.Data)

		// Store device
		if deviceId != "" && deviceName != "" {
			deviceIds = append(deviceIds, deviceId)
			deviceNames = append(deviceNames, deviceName)
		}
	})

	// Select a device (pre-set to 0 to default to the only device if only a single device is found)
	selectedDevice := 0
	if len(deviceNames) == 0 {
		return ctx, nil, errors.New("No devices found to authenticate with")
	} else if len(deviceNames) > 1 {
		// Prompt user to select a device
		if loginDetails.MFADevice == "" || !contains(deviceNames, loginDetails.MFADevice) {
			selectedDevice = prompter.Choose("Select device", deviceNames)
		} else {
			for i, item := range deviceNames {
				if item == loginDetails.MFADevice {
					selectedDevice = i
					break
				}
			}
		}
	}
	deviceSelected = true
	logger.Debugf("Selected device %s (ID: %s)\n", deviceNames[selectedDevice], deviceIds[selectedDevice])

	// Build form
	form, err := page.NewFormFromDocument(doc, "form#device-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting device form")
	}
	form.URL = resp.Request.URL.String()
	form.Values.Set("deviceId", deviceIds[selectedDevice])
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSwipe(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	log.Println("Sending swipe to phone...")

	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	// Intercept and request user to select a device if they have not already
	if loginDetails.MFAPrompt && !deviceSelected {
		return ctx, checkForDevices(), nil
	}

	form, err := page.NewFormFromDocument(doc, "#form1")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting swipe status form")
	}

	// poll status. request must specifically be a GET
	form.Method = "GET"
	req, err := form.BuildRequest()
	if err != nil {
		return ctx, nil, err
	}

	for {
		time.Sleep(2 * time.Second)

		res, err := ac.client.Do(req)
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error polling swipe status")
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error parsing body from swipe status response")
		}

		resp := string(body)

		pingfedMFAStatusResponse := gjson.Get(resp, "status").String()

		//ASYNC_AUTH_WAIT indicates we keep going
		//OK indicates someone swiped
		//DEVICE_CLAIM_TIMEOUT indicates nobody swiped
		//otherwise loop forever?

		if pingfedMFAStatusResponse == "OK" {
			log.Println("Received swipe")
			break
		} else if pingfedMFAStatusResponse == "DEVICE_CLAIM_TIMEOUT" || pingfedMFAStatusResponse == "TIMEOUT" {
			log.Println("Swipe timed out")
			break
		}
	}

	// now build a request for getting response of MFA
	form, err = page.NewFormFromDocument(doc, "#reponseView")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting swipe response form")
	}
	req, err = form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleFormRedirect(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting redirect form")
	}
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleWebAuthn(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting webauthn form")
	}
	form.Values.Set("isWebAuthnSupportedByBrowser", "true")
	req, err := form.BuildRequest()
	return ctx, req, err
}

func docIsError(doc *goquery.Document) bool {
	return doc.Has("div.ping-error").Size() == 1 && doc.Has("div#error-details-div").Size() == 1
}

func docIsPreLogin(doc *goquery.Document) bool {
	return doc.Has("input[name=\"subject\"]").Size() == 1
}

func docIsLogin(doc *goquery.Document) bool {
	return doc.Has("#login-password-field").Size() == 1 &&
		doc.Has("input[name=\"pf.pass\"]").Size() == 1
}

func docIsToken(doc *goquery.Document) bool {
	return doc.Has("#login-password-field").Size() == 0 &&
		doc.Has("input[name=\"pf.pass\"]").Size() == 1
}

func docIsChallenge(doc *goquery.Document) bool {
	return doc.Has("input[name=\"pf.challengeResponse\"]").Size() == 1
}

func docIsSiteMinderLogin(doc *goquery.Document) bool {
	return doc.Has("div#loginFrm").Size() == 1
}

func docIsMfaSpinner(doc *goquery.Document) bool {
	return doc.Has("div#mfa-ui-spinner").Size() == 1
}

func docIsOTP(doc *goquery.Document) bool {
	return doc.Has("form#otp-form").Size() == 1 && !docIsSecurityKeyAuth(doc)
}

func docIsSelectDevice(doc *goquery.Document) bool {
	return doc.Has("form#device-form").Size() == 1
}

func docIsSecurityKeyAuth(doc *goquery.Document) bool {
	return doc.Has("input[name=\"publicKeyCredentialRequestOptions\"]").Size() == 1
}

func docIsPingAuth(doc *goquery.Document) bool {
	return doc.Has("form#form1").Size() == 1
}

func docIsSwipe(doc *goquery.Document) bool {
	return doc.Has("form#form1").Size() == 1 && doc.Has("form#reponseView").Size() == 1
}

func docIsFormRedirect(doc *goquery.Document) bool {
	return doc.Has("input[name=\"ppm_request\"]").Size() == 1
}

func docIsWebAuthn(doc *goquery.Document) bool {
	return doc.Has("input[name=\"isWebAuthnSupportedByBrowser\"]").Size() == 1
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
	return doc.Find("form[action=\"https://signin.aws.amazon.com/saml\"]").Size() == 1 ||
		doc.Find("form[action=\"https://signin.amazonaws-us-gov.com/saml\"]").Size() == 1
}

func extractSAMLResponse(doc *goquery.Document) (v string, ok bool) {
	return doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
}

// ensures given url is an absolute URL. if not, it will be combined with the base URL
func makeAbsoluteURL(v string, base string) string {
	if u, err := url.ParseRequestURI(v); err == nil && !u.IsAbs() {
		baseUri, err := url.Parse(base)
		if err != nil {
			panic(err)
		}

		if strings.HasPrefix(v, baseUri.Path) {
			baseUri.Path = v
			return baseUri.String()
		} else {
			return fmt.Sprintf("%s%s", base, v)
		}
	}
	return v
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// checkForDevices : Generates a GET request to the devices page on PingOne
func checkForDevices() *http.Request {
	log.Println("Checking for additional devices...")

	// Check for device change
	req, err := http.NewRequest("GET", "https://authenticator.pingone.com/pingid/ppm/devices", nil)
	if err != nil {
		return nil
	}

	// Add cookies to the request
	addCookies(req, resp.Cookies())

	return req
}

// addCookies : Adds the correct cookies to the request
func addCookies(req *http.Request, reqCookies []*http.Cookie) {
	for _, cookie := range reqCookies {
		if cookie.Domain == req.URL.Host {
			req.AddCookie(cookie)
		}
	}
}
