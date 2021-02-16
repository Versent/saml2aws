package pingone

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/page"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

var logger = logrus.WithField("provider", "pingone")

// Client wrapper around PingOne + PingId enabling authentication and retrieval of assertions
type Client struct {
	provider.ValidateBase

	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// SuccessOrRedirectOrUnauthorizedResponseValidator also allows 401
func SuccessOrRedirectOrUnauthorizedResponseValidator(req *http.Request, resp *http.Response) error {

	validatorResponse := provider.SuccessOrRedirectResponseValidator(req, resp)

	if validatorResponse == nil || resp.StatusCode == 401 {
		return nil
	}

	return validatorResponse
}

// New create a new PingOne client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// assign a response validator to ensure all responses are either success or a redirect
	// this is to avoid have explicit checks for every single response
	client.CheckResponseStatus = SuccessOrRedirectOrUnauthorizedResponseValidator

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

type ctxKey string

// Authenticate Authenticate to PingOne and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	req, err := http.NewRequest("GET", loginDetails.URL, nil)
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

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	var handler func(context.Context, *goquery.Document, *http.Response) (context.Context, *http.Request, error)

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
	} else if docIsLogin(doc) {
		logger.WithField("type", "login").Debug("doc detect")
		handler = ac.handleLogin
	} else if docIsCheckWebAuthn(doc) {
		logger.WithField("type", "check-webauthn").Debug("doc detect")
		handler = ac.handleCheckWebAuthn
	} else if docIsFormSelectDevice(doc) {
		logger.WithField("type", "select-device").Debug("doc detect")
		handler = ac.handleFormSelectDevice
	} else if docIsOTP(doc) {
		logger.WithField("type", "otp").Debug("doc detect")
		handler = ac.handleOTP
	} else if docIsSwipe(doc) {
		logger.WithField("type", "swipe").Debug("doc detect")
		handler = ac.handleSwipe
	} else if docIsFormRedirect(doc) {
		logger.WithField("type", "form-redirect").Debug("doc detect")
		handler = ac.handleFormRedirect
	} else if docIsRefresh(doc) {
		logger.WithField("type", "refresh").Debug("doc detect")
		handler = ac.handleRefresh
	}
	if handler == nil {
		html, _ := doc.Selection.Html()
		logger.WithField("doc", html).Debug("Unknown document type")
		return "", fmt.Errorf("Unknown document type")
	}

	ctx, req, err = handler(ctx, doc, res)
	if err != nil {
		return "", err
	}
	return ac.follow(ctx, req)
}

func (ac *Client) handleLogin(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	baseURL := makeBaseURL(res.Request.URL)
	logger.WithField("baseURL", baseURL).Debug("base url")

	form.Values.Set("pf.username", loginDetails.Username)
	form.Values.Set("pf.pass", loginDetails.Password)
	form.URL, err = makeAbsoluteURL(form.URL, baseURL)
	if err != nil {
		return ctx, nil, err
	}

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleCheckWebAuthn(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting login form")
	}

	form.Values.Set("isWebAuthnSupportedByBrowser", "false")

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleOTP(ctx context.Context, doc *goquery.Document, _ *http.Response) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "#otp-form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting OTP form")
	}

	token := prompter.StringRequired("Enter passcode")
	form.Values.Set("otp", token)
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleSwipe(ctx context.Context, doc *goquery.Document, _ *http.Response) (context.Context, *http.Request, error) {
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

func (ac *Client) handleFormRedirect(ctx context.Context, doc *goquery.Document, _ *http.Response) (context.Context, *http.Request, error) {
	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting redirect form")
	}
	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleRefresh(ctx context.Context, doc *goquery.Document, _ *http.Response) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building request")
	}

	return ctx, req, err
}

func (ac *Client) handleFormSelectDevice(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	deviceList := make(map[string]string)
	var deviceNameList []string

	doc.Find("ul.device-list > li").Each(func(_ int, s *goquery.Selection) {
		deviceId, _ := s.Attr("data-id")
		deviceName, _ := s.Find("a > div.device-name").Html()

		logger.WithField("device name", deviceName).WithField("device id", deviceId).Debug("Select Device")
		deviceList[deviceName] = deviceId
		deviceNameList = append(deviceNameList, deviceName)
	})

	var chooseDevice = prompter.Choose("Select which MFA Device to use", deviceNameList)

	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting select device form")
	}

	form.Values.Set("deviceId", deviceList[deviceNameList[chooseDevice]])
	form.URL, err = makeAbsoluteURL(form.URL, makeBaseURL(res.Request.URL))
	if err != nil {
		return ctx, nil, err
	}

	logger.WithField("value", form.Values.Encode()).Debug("Select Device")
	req, err := form.BuildRequest()
	return ctx, req, err
}

func docIsLogin(doc *goquery.Document) bool {
	return doc.Has("input[name=\"pf.pass\"]").Size() == 1
}

func docIsOTP(doc *goquery.Document) bool {
	return doc.Has("form#otp-form").Size() == 1
}

func docIsCheckWebAuthn(doc *goquery.Document) bool {
	return doc.Has("input[name=\"isWebAuthnSupportedByBrowser\"]").Size() == 1
}

func docIsSwipe(doc *goquery.Document) bool {
	return doc.Has("form#form1").Size() == 1 && doc.Has("form#reponseView").Size() == 1
}

func docIsFormRedirect(doc *goquery.Document) bool {
	return doc.Has("input[name=\"ppm_request\"]").Size() == 1 || doc.Find("form[action=\"https://authenticator.pingone.com/pingid/ppm/auth\"]").Size() == 1
}

func docIsFormSamlRequest(doc *goquery.Document) bool {
	return doc.Find("input[name=\"SAMLRequest\"]").Size() == 1
}

func docIsFormResume(doc *goquery.Document) bool {
	return doc.Find("input[name=\"RelayState\"]").Size() == 1 || doc.Find("input[name=\"Resume\"]").Size() == 1
}

func docIsFormRedirectToAWS(doc *goquery.Document) bool {
	return doc.Find("form[action=\"https://signin.aws.amazon.com/saml\"]").Size() == 1
}

func docIsFormSelectDevice(doc *goquery.Document) bool {
	return doc.Has("form[name=\"device-form\"]").Size() == 1
}

func docIsRefresh(doc *goquery.Document) bool {
	return doc.Has("meta[http-equiv=\"refresh\"]").Size() == 1
}

func extractSAMLResponse(doc *goquery.Document) (v string, ok bool) {

	return doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
}

func makeBaseURL(url *url.URL) string {
	return url.Scheme + "://" + url.Hostname()
}

// ensures given url is an absolute URL. if not, it will be combined with the base URL
func makeAbsoluteURL(v string, base string) (string, error) {
	logger.WithField("base", base).WithField("v", v).Debug("make absolute url")
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	pathURL, err := url.ParseRequestURI(v)
	if err != nil {
		return "", err
	}
	if pathURL.IsAbs() {
		return pathURL.String(), nil
	}
	return baseURL.ResolveReference(pathURL).String(), nil
}
