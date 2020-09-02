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

var cookies = []*http.Cookie{}
var resp *http.Response

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
	resp = res
	if err != nil {
		return "", errors.Wrap(err, "error following")
	}
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	//html, _ := doc.Html()
	//logger.Debugf("Headers: %+v", res.Header)
	//logger.Debugf("Body: %+v", html)

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
	} else if docIsOTP(doc) {
		logger.WithField("type", "otp").Debug("doc detect")
		handler = ac.handleOTP
	} else if docIsMfaSpinner(doc) {
		logger.WithField("type", "mfa-spinner").Debug("doc detect")
		handler = ac.handleMfaSpinner
	} else if docIsSwipe(doc) {
		logger.WithField("type", "swipe").Debug("doc detect")
		handler = ac.handleSwipe
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

	ctx, req, err = handler(ctx, doc)
	if err != nil {
		return "", err
	}

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

	for _, cookie := range cookies {
		req.AddCookie(cookie)
		//logger.Debugf("Cookie: %s=%s", cookie.Name, cookie.Value)
	}

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
	if loginDetails.MFAToken == "" {
		token = prompter.Password("Enter PIN + Token Code / Passcode")
	}

	form.Values.Set("username", loginDetails.Username)
	form.Values.Set("PASSWORD", token)
	form.URL = resp.Request.URL.String()

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleOTP(ctx context.Context, doc *goquery.Document) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "#otp-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting OTP form")
	}

	token := prompter.Password("Enter passcode")
	form.Values.Set("otp", token)

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

	log.Println("Sending swipe to phone...")

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
