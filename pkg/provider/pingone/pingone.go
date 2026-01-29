package pingone

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// New create a new PingOne client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// assign a response validator to ensure all responses are either success or a redirect
	// this is to avoid have explicit checks for every single response
	client.CheckResponseStatus = provider.SuccessOrRedirectOrUnauthorizedResponseValidator

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

	if docIsFormRedirectToTarget(doc, ac.idpAccount.TargetURL) {
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
	} else if docIsIdentifierFirst(doc) {
		logger.WithField("type", "identifier-first").Debug("doc detect")
		handler = ac.handleIdentifierFirst
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
	} else if docIsDuoPluginForm(doc) {
		logger.WithField("type", "duo-plugin-form").Debug("doc detect")
		handler = ac.handleDuoPluginForm
	} else if docIsDuoPrompt(doc) {
		logger.WithField("type", "duo-prompt").Debug("doc detect")
		handler = ac.handleDuoPrompt
	} else if docIsAutoPostForm(doc) {
		logger.WithField("type", "auto-post-form").Debug("doc detect")
		handler = ac.handleFormRedirect
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

		body, err := io.ReadAll(res.Body)
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

func (ac *Client) handleRefresh(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	// Try to extract the refresh URL from meta tag
	var refreshURL string
	doc.Find("meta[http-equiv=\"refresh\"]").Each(func(_ int, s *goquery.Selection) {
		if content, ok := s.Attr("content"); ok {
			// Parse content like "0;url=https://example.com/path"
			parts := strings.SplitN(content, "url=", 2)
			if len(parts) == 2 {
				refreshURL = strings.TrimSpace(parts[1])
			} else {
				// Try with URL= (case insensitive)
				parts = strings.SplitN(content, "URL=", 2)
				if len(parts) == 2 {
					refreshURL = strings.TrimSpace(parts[1])
				}
			}
		}
	})

	// If we found a refresh URL, use it
	if refreshURL != "" {
		logger.WithField("refreshURL", refreshURL).Debug("following meta refresh URL")
		req, err := http.NewRequest("GET", refreshURL, nil)
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error building refresh request")
		}
		return ctx, req, err
	}

	// Fallback to original login URL
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	logger.WithField("url", loginDetails.URL).Debug("falling back to original login URL")
	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building request")
	}

	return ctx, req, err
}

func (ac *Client) handleIdentifierFirst(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	loginDetails, ok := ctx.Value(ctxKey("login")).(*creds.LoginDetails)
	if !ok {
		return ctx, nil, fmt.Errorf("no context value for 'login'")
	}

	form, err := page.NewFormFromDocument(doc, "form")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting identifier-first form")
	}

	baseURL := makeBaseURL(res.Request.URL)
	logger.WithField("baseURL", baseURL).Debug("identifier-first base url")

	form.Values.Set("subject", loginDetails.Username)
	form.URL, err = makeAbsoluteURL(form.URL, baseURL)
	if err != nil {
		return ctx, nil, err
	}

	req, err := form.BuildRequest()
	return ctx, req, err
}

func (ac *Client) handleDuoPluginForm(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	// Manually extract form values since the form may not have an action attribute
	// and NewFormFromDocument crashes when doc.Url is nil
	formSelection := doc.Find("#plugin_form").First()
	if formSelection.Size() != 1 {
		return ctx, nil, fmt.Errorf("could not find Duo plugin form")
	}

	formURL := res.Request.URL.String()
	if action, ok := formSelection.Attr("action"); ok && action != "" {
		var err error
		formURL, err = makeAbsoluteURL(action, makeBaseURL(res.Request.URL))
		if err != nil {
			return ctx, nil, err
		}
	}

	formValues := &url.Values{}
	formSelection.Find("input").Each(func(_ int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		val, _ := s.Attr("value")
		formValues.Add(name, val)
	})

	logger.WithField("url", formURL).Debug("Duo plugin form")

	req, err := http.NewRequest("POST", formURL, nil)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building Duo plugin form request")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Body = io.NopCloser(strings.NewReader(formValues.Encode()))

	return ctx, req, err
}

func (ac *Client) handleDuoPrompt(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	// Extract the login form
	formSelection := doc.Find("#login-form").First()
	if formSelection.Size() != 1 {
		return ctx, nil, fmt.Errorf("could not find Duo login form")
	}

	baseURL := makeBaseURL(res.Request.URL)

	// Get form action
	formURL := res.Request.URL.String()
	if action, ok := formSelection.Attr("action"); ok && action != "" {
		var err error
		formURL, err = makeAbsoluteURL(action, baseURL)
		if err != nil {
			return ctx, nil, err
		}
	}

	// Collect form values - only take the first value for each name
	formValues := &url.Values{}
	seenNames := make(map[string]bool)
	formSelection.Find("input[type=\"hidden\"]").Each(func(_ int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok || seenNames[name] {
			return
		}
		val, _ := s.Attr("value")
		formValues.Set(name, val)
		seenNames[name] = true
	})

	// Get the preferred device from the form
	device := formValues.Get("preferred_device")
	if device == "" {
		// Try to get from select element
		formSelection.Find("select[name=\"device\"] option").First().Each(func(_ int, s *goquery.Selection) {
			if val, ok := s.Attr("value"); ok {
				device = val
			}
		})
	}
	if device == "" {
		device = "phone1" // fallback default
	}
	formValues.Set("device", device)

	// Also get XSRF token from outside the form if present
	xsrf := formValues.Get("_xsrf")
	if xsrf == "" {
		doc.Find("input[name=\"_xsrf\"]").Each(func(_ int, s *goquery.Selection) {
			if val, ok := s.Attr("value"); ok && xsrf == "" {
				xsrf = val
			}
		})
	}

	// Set factor to Duo Push
	formValues.Set("factor", "Duo Push")

	logger.WithField("device", device).WithField("factor", "Duo Push").Debug("Duo parameters")

	logger.WithField("url", formURL).Debug("Duo prompt - sending push")
	fmt.Println("Sending Duo push notification...")

	// Submit the form to initiate Duo Push
	pushReq, err := http.NewRequest("POST", formURL, strings.NewReader(formValues.Encode()))
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error building Duo push request")
	}
	pushReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	pushRes, err := ac.client.Do(pushReq)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error sending Duo push")
	}

	// Parse the response to get the txid
	pushBody, err := io.ReadAll(pushRes.Body)
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error reading Duo push response")
	}

	pushResponse := string(pushBody)
	logger.WithField("response", pushResponse).Debug("Duo push response")

	// Try to parse as JSON first (Duo API response)
	txid := gjson.Get(pushResponse, "response.txid").String()
	if txid == "" {
		// Maybe it's HTML, try to parse it
		pushDoc, err := goquery.NewDocumentFromReader(strings.NewReader(pushResponse))
		if err == nil {
			// Look for txid in the page
			pushDoc.Find("input[name=\"txid\"]").Each(func(_ int, s *goquery.Selection) {
				if val, ok := s.Attr("value"); ok {
					txid = val
				}
			})
		}
	}

	sid := formValues.Get("sid")
	statusURL, err := makeAbsoluteURL("/frame/status", baseURL)
	if err != nil {
		return ctx, nil, err
	}

	logger.WithField("txid", txid).WithField("sid", sid).Debug("Duo polling parameters")

	// Poll for Duo status
	fmt.Println("Waiting for Duo approval...")
	for i := 0; i < 60; i++ { // 60 attempts, 2 seconds each = 2 minutes timeout
		time.Sleep(2 * time.Second)

		statusValues := &url.Values{}
		statusValues.Set("sid", sid)
		statusValues.Set("txid", txid)
		if xsrf != "" {
			statusValues.Set("_xsrf", xsrf)
		}

		statusReq, err := http.NewRequest("POST", statusURL, strings.NewReader(statusValues.Encode()))
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error building Duo status request")
		}
		statusReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		statusRes, err := ac.client.Do(statusReq)
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error polling Duo status")
		}

		body, err := io.ReadAll(statusRes.Body)
		if err != nil {
			return ctx, nil, errors.Wrap(err, "error reading Duo status response")
		}

		statusResponse := string(body)
		logger.WithField("status", statusResponse).Debug("Duo status response")

		// Check the status_code for the actual authentication state
		stat := gjson.Get(statusResponse, "stat").String()
		statusCode := gjson.Get(statusResponse, "response.status_code").String()
		result := gjson.Get(statusResponse, "response.result").String()

		logger.WithField("stat", stat).WithField("status_code", statusCode).WithField("result", result).Debug("Duo status parsed")

		// Check for approval (status_code "allow" means approved)
		if statusCode == "allow" || result == "SUCCESS" {
			logger.Debug("Duo push approved")
			fmt.Println("Duo push approved!")

			// Get the result URL or use oidc_exit based on post_auth_action
			resultURL := gjson.Get(statusResponse, "response.result_url").String()
			postAuthAction := gjson.Get(statusResponse, "response.post_auth_action").String()
			duoCookie := gjson.Get(statusResponse, "response.cookie").String()

			// If there's a result_url, we need to call it first to get the cookie
			if resultURL != "" {
				resultURL, err = makeAbsoluteURL(resultURL, baseURL)
				if err != nil {
					return ctx, nil, err
				}

				resultValues := &url.Values{}
				resultValues.Set("sid", sid)
				if xsrf != "" {
					resultValues.Set("_xsrf", xsrf)
				}

				logger.WithField("url", resultURL).Debug("Duo fetching result")
				resultReq, err := http.NewRequest("POST", resultURL, strings.NewReader(resultValues.Encode()))
				if err != nil {
					return ctx, nil, errors.Wrap(err, "error building Duo result request")
				}
				resultReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				resultRes, err := ac.client.Do(resultReq)
				if err != nil {
					return ctx, nil, errors.Wrap(err, "error fetching Duo result")
				}

				resultBody, err := io.ReadAll(resultRes.Body)
				if err != nil {
					return ctx, nil, errors.Wrap(err, "error reading Duo result")
				}

				resultResponse := string(resultBody)
				logger.WithField("result", resultResponse).Debug("Duo result response")

				// Get cookie from result
				duoCookie = gjson.Get(resultResponse, "response.cookie").String()
				if duoCookie == "" {
					duoCookie = gjson.Get(resultResponse, "response.parent").String()
				}
			}

			// Now call the OIDC exit
			if postAuthAction == "oidc_exit" || resultURL == "" {
				exitURL, err := makeAbsoluteURL("/frame/prompt/oidc/exit", baseURL)
				if err != nil {
					return ctx, nil, err
				}

				exitValues := &url.Values{}
				exitValues.Set("sid", sid)
				if xsrf != "" {
					exitValues.Set("_xsrf", xsrf)
				}
				if txid != "" {
					exitValues.Set("txid", txid)
				}
				if duoCookie != "" {
					exitValues.Set("dampen_choice", "true")
				}

				logger.WithField("url", exitURL).WithField("txid", txid).Debug("Duo OIDC exit")

				req, err := http.NewRequest("POST", exitURL, strings.NewReader(exitValues.Encode()))
				if err != nil {
					return ctx, nil, errors.Wrap(err, "error building Duo exit request")
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return ctx, req, nil
			}

			return ctx, nil, fmt.Errorf("Duo approved but couldn't determine next step")
		}

		// Check for denial
		if statusCode == "deny" || result == "FAILURE" {
			reason := gjson.Get(statusResponse, "response.status").String()
			if reason == "" {
				reason = gjson.Get(statusResponse, "response.reason").String()
			}
			return ctx, nil, fmt.Errorf("Duo authentication denied: %s", reason)
		}

		// "pushed" means still waiting - continue polling
		if statusCode == "pushed" {
			continue
		}

		// Check for other failures
		if stat == "FAIL" {
			message := gjson.Get(statusResponse, "message").String()
			return ctx, nil, fmt.Errorf("Duo error: %s", message)
		}
	}

	return ctx, nil, fmt.Errorf("Duo authentication timed out")
}

func (ac *Client) handleFormSelectDevice(ctx context.Context, doc *goquery.Document, res *http.Response) (context.Context, *http.Request, error) {
	var deviceMap = findDeviceMap(doc)
	deviceNameList := make([]string, len(deviceMap))
	i := 0
	for key := range deviceMap {
		deviceNameList[i] = key
		i++
	}
	var chooseDevice = prompter.Choose("Select which MFA Device to use", deviceNameList)

	form, err := page.NewFormFromDocument(doc, "")
	if err != nil {
		return ctx, nil, errors.Wrap(err, "error extracting select device form")
	}

	form.Values.Set("deviceId", deviceMap[deviceNameList[chooseDevice]])
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

func docIsFormRedirectToTarget(doc *goquery.Document, target string) bool {
	if target == "" {
		target = "https://signin.aws.amazon.com/saml"
	}
	urlForm := fmt.Sprintf("form[action=\"%s\"]", target)
	return doc.Find(urlForm).Size() == 1
}

func docIsFormSelectDevice(doc *goquery.Document) bool {
	return doc.Has("form[name=\"device-form\"]").Size() == 1
}

func docIsRefresh(doc *goquery.Document) bool {
	return doc.Has("meta[http-equiv=\"refresh\"]").Size() == 1
}

// docIsDuoPluginForm detects Duo Security pre-auth plugin detection form
func docIsDuoPluginForm(doc *goquery.Document) bool {
	return doc.Find("form#plugin_form").Size() == 1
}

// docIsDuoPrompt detects Duo Security MFA prompt page
func docIsDuoPrompt(doc *goquery.Document) bool {
	return doc.Find("form#login-form").Size() == 1 &&
		doc.Find("input[name=\"sid\"]").Size() >= 1
}

// docIsAutoPostForm detects generic auto-POST redirect forms (like PingOne login callback)
func docIsAutoPostForm(doc *goquery.Document) bool {
	// Check for forms with tokenid (PingOne callback) or other auto-submit patterns
	hasTokenId := doc.Find("input[name=\"tokenid\"]").Size() == 1
	hasAutoSubmit := doc.Find("body[onload*=\"submit\"]").Size() == 1
	hasForm := doc.Find("form").Size() == 1
	return hasForm && (hasTokenId || hasAutoSubmit)
}

// docIsIdentifierFirst detects PingFederate Identifier-First flow
// where email/username is entered first, then password on next page
func docIsIdentifierFirst(doc *goquery.Document) bool {
	return doc.Find("input[name=\"subject\"]").Size() == 1 &&
		doc.Find("input[name=\"pf.pass\"]").Size() == 0
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

func findDeviceMap(doc *goquery.Document) map[string]string {
	deviceList := make(map[string]string)

	doc.Find("ul.device-list > li").Each(func(_ int, s *goquery.Selection) {
		deviceId, _ := s.Attr("data-id")
		deviceName, _ := s.Find("a > div.device-name").Html()
		if deviceName == "" {
			deviceName, _ = s.Find("button > div.device-name").Html()
		}

		logger.WithField("device name", deviceName).WithField("device id", deviceId).Debug("Select Device")
		deviceList[deviceName] = deviceId
	})
	return deviceList
}
