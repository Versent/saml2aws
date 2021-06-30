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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

	req, err := http.NewRequest("POST", authSubmitURL, authBody)
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
		for idx, val := range mfaOptions {
			if strings.HasPrefix(strings.ToUpper(val), oc.mfa) {
				mfaOption = idx
				break
			}
		}
	} else if len(mfaOptions) > 1 {
		mfaOption = prompter.Choose("Select which MFA option to use", mfaOptions)
	}

	factorID := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d.id", mfaOption)).String()
	oktaVerify := gjson.Get(resp, fmt.Sprintf("_embedded.factors.%d._links.verify.href", mfaOption)).String()
	mfaIdentifer := parseMfaIdentifer(resp, mfaOption)

	logger.WithField("factorID", factorID).WithField("oktaVerify", oktaVerify).WithField("mfaIdentifer", mfaIdentifer).Debug("MFA")

	if _, ok := supportedMfaOptions[mfaIdentifer]; !ok {
		return "", errors.New("unsupported mfa provider")
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
		return "", errors.Wrap(err, "error encoding verifyReq")
	}

	req, err := http.NewRequest("POST", oktaVerify, verifyBody)
	if err != nil {
		return "", errors.Wrap(err, "error building verify request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	res, err := oc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving verify response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}
	resp = string(body)

	switch mfa := mfaIdentifer; mfa {
	case IdentifierYubiMfa:
		return gjson.Get(resp, "sessionToken").String(), nil
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

		req, err = http.NewRequest("POST", oktaVerify, tokenBody)
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
		for {

			res, err = oc.client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving verify response")
			}

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving body from response")
			}

			// on 'success' status
			if gjson.Get(string(body), "status").String() == "SUCCESS" {
				fmt.Printf(" Approved\n\n")
				return gjson.Get(string(body), "sessionToken").String(), nil
			}

			// otherwise probably still waiting
			switch gjson.Get(string(body), "factorResult").String() {

			case "WAITING":
				time.Sleep(3 * time.Second)
				fmt.Printf(".")
				logger.Debug("Waiting for user to authorize login")

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
		duoHost := gjson.Get(resp, "_embedded.factor._embedded.verification.host").String()
		duoSignature := gjson.Get(resp, "_embedded.factor._embedded.verification.signature").String()
		duoSiguatres := strings.Split(duoSignature, ":")
		//duoSignatures[0] = TX
		//duoSignatures[1] = APP
		duoCallback := gjson.Get(resp, "_embedded.factor._embedded.verification._links.complete.href").String()

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

		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}

		defer res.Body.Close()

		// At this point, if device trust is enabled we need to go on that tangent
		doc, err := goquery.NewDocumentFromResponse(res)
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

			body, err = ioutil.ReadAll(res.Body)
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

		if duoMfaOption > 0 {
			duoForm.Add("device", "phone1")
			duoForm.Add("factor", duoMfaOptions[duoMfaOption])
			if duoMfaOptions[duoMfaOption] == "Passcode" {
				duoForm.Add("passcode", token)
			}
		} else {
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
		oktaForm.Add("id", factorID)
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

		verifyReq = VerifyRequest{StateToken: stateToken}
		verifyBody = new(bytes.Buffer)
		err = json.NewEncoder(verifyBody).Encode(verifyReq)
		if err != nil {
			return "", errors.Wrap(err, "error encoding verify request")
		}

		req, err = http.NewRequest("POST", oktaVerify, verifyBody)
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
		nonce := gjson.Get(resp, "_embedded.factor._embedded.challenge.challenge").String()
		credentialID := gjson.Get(resp, "_embedded.factor.profile.credentialId").String()
		version := gjson.Get(resp, "_embedded.factor.profile.version").String()
		appID := oktaOrgHost
		webauthnCallback := gjson.Get(resp, "_links.next.href").String()

		fidoClient, err := NewFidoClient(nonce,
			appID,
			version,
			credentialID,
			stateToken,
			new(U2FDeviceFinder))
		if err != nil {
			return "", err
		}

		signedAssertion, err := fidoClient.ChallengeU2F()
		if err != nil {
			return "", err
		}

		payload, err := json.Marshal(signedAssertion)
		if err != nil {
			return "", err
		}
		req, err = http.NewRequest("POST", webauthnCallback, strings.NewReader(string(payload)))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		res, err = oc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving verify response")
		}
		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}
		return gjson.GetBytes(body, "sessionToken").String(), nil
	}

	// catch all
	return "", errors.New("no mfa options provided")
}
