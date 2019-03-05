package pingfed

import (
	"context"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"encoding/base64"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/page"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "pingfed")

// Client wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// New create a new PingFed client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
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

type ctxKey string

// Authenticate Authenticate to PingFed and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	url := fmt.Sprintf("%s/idp/startSSO.ping?PartnerSpId=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building request")
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), loginDetails)
	return ac.follow(ctx, req)
}

func (ac *Client) follow(ctx context.Context, req *http.Request) (string, error) {
	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error following")
	}
	doc, err := goquery.NewDocumentFromResponse(res)
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
	} else if docIsLogin(doc) {
		logger.WithField("type", "login").Debug("doc detect")
		handler = ac.handleLogin
	} else if docIsOTP(doc) {
		logger.WithField("type", "otp").Debug("doc detect")
		handler = ac.handleOTP
	} else if docIsSwipe(doc) {
		logger.WithField("type", "swipe").Debug("doc detect")
		handler = ac.handleSwipe
	} else if docIsFormRedirect(doc) {
		logger.WithField("type", "form-redirect").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsWebAuthn(doc) {
		logger.WithField("type", "webauthn").Debug("doc detect")
		handler = ac.handleWebAuthn
	} else if docIsDuoIFrame(doc) {
		logger.WithField("type", "duo-iframe").Debug("doc detect")
		handler = ac.handleDuoIFrame
	} else if docIsDuoTwoFactor(doc) {
		logger.WithField("type", "duo-2factor").Debug("doc detect")
		handler = ac.handleDuo2Factor
	} else if docIsDuoStat(doc) {
		logger.WithField("type", "duo-stat").Debug("doc detect")
		handler = ac.handleDuoStat
	} else if docIsDuoPush(doc) {
		logger.WithField("type", "duo-push").Debug("doc detect")
		handler = ac.handleDuoPush
	} else if docIsDuoCookie(doc) {
		logger.WithField("type", "duo-cookie").Debug("doc detect")
		handler = ac.handleDuoCookie
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
	return ac.follow(ctx, req)
}

func (ac *Client) handleDuoCookie(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	htmlResp, _ := doc.Selection.Html()
	htmlResp = html.UnescapeString(htmlResp)
	app, ok := ctx.Value(ctxKey("app")).(string)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'app'")
	}
	parent, ok := ctx.Value(ctxKey("parent")).(string)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'parent'")
	}

	duoTxCookie := gjson.Get(htmlResp, "response.cookie").String()
	if duoTxCookie == "" {
		return ctx, nil, errors.New("duoResultSubmit: Unable to get response.cookie")
	}

	idpForm := url.Values{}
	idpForm.Add("_eventId", "proceed")
	idpForm.Add("sig_response", duoTxCookie+":"+app)

	req, err := http.NewRequest("POST", parent, strings.NewReader(idpForm.Encode()))
	if err != nil {
		return ctx, nil, errors.New("error posting multi-factor verification to shibboleth server")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return ctx, req, nil
}

func (ac *Client) handleDuoIFrame(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	html, _ := doc.Selection.Html()
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}
	duoHost, postAction, tx, app := parseTokens(html)
	ctx = context.WithValue(ctx, ctxKey("duoHost"), duoHost)

	parent := fmt.Sprintf(loginDetails.URL + postAction)

	// initiate duo mfa to get sid
	duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)
	ctx = context.WithValue(ctx, ctxKey("duoSubmitURL"), duoSubmitURL)
	ctx = context.WithValue(ctx, ctxKey("app"), app)
	ctx = context.WithValue(ctx, ctxKey("parent"), parent)

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
		return ctx, nil, errors.Wrap(err, "error building authentication request")
	}
	q := req.URL.Query()
	q.Add("tx", tx)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return ctx, req, nil
}
func (ac *Client) handleDuoPush(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	htmlResp, _ := doc.Selection.Html()
	htmlResp = html.UnescapeString(htmlResp)
	duoTxResult := gjson.Get(htmlResp, "response.result").String()
	duoResultURL := gjson.Get(htmlResp, "response.result_url").String()
	duoHost, ok := ctx.Value(ctxKey("duoHost")).(string)
	duoSubmitURL := fmt.Sprintf("https://%s/frame/status", duoHost)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'duoHost'")
	}

	duoForm, ok := ctx.Value(ctxKey("duoForm")).(url.Values)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}
	fmt.Println(gjson.Get(htmlResp, "response.status").String())

	if duoTxResult != "SUCCESS" {
		//poll as this is likely a push request
		for {

			time.Sleep(3 * time.Second)

			req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
			if err != nil {
				return ctx, nil, errors.Wrap(err, "error building authentication request")
			}

			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			res, err := ac.client.Do(req)
			if err != nil {
				return ctx, nil, errors.Wrap(err, "error retrieving verify response")
			}

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return ctx, nil, errors.Wrap(err, "error retrieving body from response")
			}

			resp := string(body)

			duoTxResult = gjson.Get(resp, "response.result").String()
			duoResultURL = gjson.Get(resp, "response.result_url").String()

			fmt.Println(gjson.Get(resp, "response.status").String())

			if duoTxResult == "FAILURE" {
				return ctx, nil, errors.Wrap(err, "failed to authenticate device")
			}

			if duoTxResult == "SUCCESS" {
				break
			}
		}
	}
	duoRequestURL := fmt.Sprintf("https://%s%s", duoHost, duoResultURL)
	req, err := http.NewRequest("POST", duoRequestURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error constructing request object to result url")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return ctx, req, nil
}

func (ac *Client) handleDuo2Factor(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}
	duoHost, ok := ctx.Value(ctxKey("duoHost")).(string)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'duoHost'")
	}
	duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
	if !ok {
		return ctx, nil, errors.New("unable to locate saml response")
	}
	duoSID = html.UnescapeString(duoSID)
	ctx = context.WithValue(ctx, ctxKey("duoSID"), duoSID)
	//prompt for mfa type
	//supporting push, call, and passcode for now

	var token string

	var duoMfaOptions = []string{
		"Duo Push",
		"Phone Call",
		"Passcode",
	}
	duoMfaOption := -1
	if loginDetails.DuoMFAOption != "" {
		for idx, val := range duoMfaOptions {
			if val == loginDetails.DuoMFAOption {
				duoMfaOption = idx
				break
			}
		}
		if duoMfaOption == -1 {
			return ctx, nil, errors.New("error unable to find duo mfa option selected")
		}
	} else {
		duoMfaOption = prompter.Choose("Select a DUO MFA Option", duoMfaOptions)

	}
	if duoMfaOptions[duoMfaOption] == "Passcode" {
		//get users DUO MFA Token
		token = prompter.StringRequired("Enter passcode")
	}

	// send mfa auth request
	duoSubmitURL := fmt.Sprintf("https://%s/frame/prompt", duoHost)

	duoForm := url.Values{}
	duoForm.Add("sid", duoSID)
	duoForm.Add("device", "phone1")
	duoForm.Add("factor", duoMfaOptions[duoMfaOption])
	duoForm.Add("out_of_date", "false")
	if duoMfaOptions[duoMfaOption] == "Passcode" {
		duoForm.Add("passcode", token)
	}

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return ctx, req, nil
}

func (ac *Client) handleDuoStat(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	body, _ := doc.Selection.Html()
	duoHost, ok := ctx.Value(ctxKey("duoHost")).(string)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'duoHost'")
	}
	duoSID, ok := ctx.Value(ctxKey("duoSID")).(string)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'duoSID'")
	}
	body = html.UnescapeString(body)
	duoTxStat := gjson.Get(body, "stat").String()
	duoTxID := gjson.Get(body, "response.txid").String()
	if duoTxStat != "OK" {
		return ctx, nil, errors.New("error authenticating mfa device")
	}

	// get duo cookie
	duoSubmitURL := fmt.Sprintf("https://%s/frame/status", duoHost)
	duoForm := url.Values{}
	duoForm.Add("sid", duoSID)
	duoForm.Add("txid", duoTxID)
	ctx = context.WithValue(ctx, ctxKey("duoForm"), duoForm)
	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return ctx, req, nil
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

func (ac *Client) handleOTP(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "#otp-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting OTP form")
	}

	token := prompter.StringRequired("Enter passcode")
	form.Values.Set("otp", token)
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSwipe(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
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
		time.Sleep(3 * time.Second)

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

		if pingfedMFAStatusResponse == "OK" || pingfedMFAStatusResponse == "DEVICE_CLAIM_TIMEOUT" || pingfedMFAStatusResponse == "TIMEOUT" {
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
	form.Values.Set("isWebAuthnSupportedByBrowser", "false")
	req, err := form.BuildRequest()
	return ctx, req, err
}

func docIsLogin(doc *goquery.Document) bool {
	return doc.Has("input[name=\"pf.pass\"]").Size() == 1
}

func docIsOTP(doc *goquery.Document) bool {
	return doc.Has("form#otp-form").Size() == 1
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
	return doc.Find("form[action=\"https://signin.aws.amazon.com/saml\"]").Size() == 1
}

func extractSAMLResponse(doc *goquery.Document) (v string, ok bool) {
	return doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
}

func docIsDuoIFrame(doc *goquery.Document) bool {
	return doc.Find("title").Text() == "Duo Security Two-Factor Authentication"
}

func docIsDuoTwoFactor(doc *goquery.Document) bool {
	return doc.Find("title").Text() == "\nTwo-Factor Authentication\n"
}

func docIsDuoStat(doc *goquery.Document) bool {
	htmlResp, _ := doc.Selection.Html()
	htmlResp = html.UnescapeString(htmlResp)
	return strings.Contains(htmlResp, "stat") && strings.Contains(htmlResp, "txid")
}

func docIsDuoPush(doc *goquery.Document) bool {
	htmlResp, _ := doc.Selection.Html()
	htmlResp = html.UnescapeString(htmlResp)
	return gjson.Get(htmlResp, "response.status_code").String() == "pushed"
}

func docIsDuoCookie(doc *goquery.Document) bool {
	htmlResp, _ := doc.Selection.Html()
	htmlResp = html.UnescapeString(htmlResp)
	return strings.Contains(htmlResp, "cookie") && strings.Contains(htmlResp, "stat")
}

// ensures given url is an absolute URL. if not, it will be combined with the base URL
func makeAbsoluteURL(v string, base string) string {
	if u, err := url.ParseRequestURI(v); err == nil && !u.IsAbs() {
		return fmt.Sprintf("%s%s", base, v)
	}
	return v
}

func parseTokens(blob string) (string, string, string, string) {

	hostRgx := regexp.MustCompile(`'host': '(.*?)'`)
	sigRgx := regexp.MustCompile(`'sig_request': '(.*?)'`)
	dpaRgx := regexp.MustCompile(`'post_action': '(.*?)'`)
	dataSigRequest := sigRgx.FindStringSubmatch(blob)
	duoHost := hostRgx.FindStringSubmatch(blob)
	postAction := dpaRgx.FindStringSubmatch(blob)
	duoSignatures := strings.Split(dataSigRequest[1], ":")
	return duoHost[1], postAction[1], duoSignatures[0], duoSignatures[1]
}
