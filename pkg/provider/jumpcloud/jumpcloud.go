package jumpcloud

import (
	"bytes"
	"encoding/json"
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
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

const (
	jcSSOBaseURL      = "https://sso.jumpcloud.com/"
	xsrfURL           = "https://console.jumpcloud.com/userconsole/xsrf"
	authSubmitURL     = "https://console.jumpcloud.com/userconsole/auth"
	webauthnSubmitURL = "https://console.jumpcloud.com/userconsole/auth/webauthn"
	duoAuthSubmitURL  = "https://console.jumpcloud.com/userconsole/auth/duo"

	IdentifierTotpMfa = "totp"
	IdentifierDuoMfa  = "duo"
	IdentifierU2F     = "webauthn"
)

var (
	supportedMfaOptions = map[string]string{
		IdentifierTotpMfa: "TOTP MFA authentication",
		IdentifierDuoMfa:  "DUO MFA authentication",
		IdentifierU2F:     "FIDO WebAuthn authentication",
	}
)

// Client is a wrapper representing a JumpCloud SAML client
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
	mfa    string
}

// XSRF is for unmarshalling the xsrf token in the response
type XSRF struct {
	Token string `json:"xsrf"`
}

// AuthRequest is to be sent to JumpCloud as the auth req body
type AuthRequest struct {
	Context    string
	RedirectTo string
	Email      string
	Password   string
	OTP        string
}

// JCRedirect is for unmarshalling the redirect address from the response after the auth
type JCRedirect struct {
	Address string `json:"redirectTo"`
}

type JCMessage struct {
	Message string `json:"message"`
}

// New creates a new JumpCloud client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
		mfa:    idpAccount.MFA,
	}, nil
}

// Authenticate logs into JumpCloud and returns a SAML response
func (jc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	var samlAssertion string
	var a AuthRequest
	re := regexp.MustCompile(jcSSOBaseURL)

	// Start by getting the XSRF Token
	res, err := jc.client.Get(xsrfURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving XSRF Token")
	}
	defer res.Body.Close()

	// Grab the web response that has the xsrf in it
	xsrfBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error reading body of XSRF response")
	}

	// Unmarshall the answer and store the token
	var x = new(XSRF)
	err = json.Unmarshal(xsrfBody, &x)
	if err != nil {
		log.Fatalf("Error unmarshalling xsrf response! %v", err)
	}

	// Populate our Auth body for the POST
	a.Context = "sso"
	a.RedirectTo = re.ReplaceAllString(loginDetails.URL, "")
	a.Email = loginDetails.Username
	a.Password = loginDetails.Password

	authBody, err := json.Marshal(a)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build auth request body")
	}

	// Generate our auth request
	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(string(authBody)))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	// Add the necessary headers to the auth request
	req.Header.Add("X-Xsrftoken", x.Token)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	res, err = jc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form")
	}
	defer res.Body.Close()

	// Check if we get a 401.  If we did, and MFA is required, get the OTP and resubmit.
	// Otherwise log the authentication message as a fatal error.
	if res.StatusCode == 401 {

		// Grab the body from the response that has the message in it.
		messageBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "Error reading body")
		}

		// Unmarshall the body to get the message.
		var jcmsg = new(JCMessage)
		err = json.Unmarshal(messageBody, &jcmsg)
		if err != nil {
			log.Fatalf("Error unmarshalling message response! %v", err)
		}

		// If the error indicates something other than missing MFA, then it's fatal.
		if jcmsg.Message != "MFA required." {
			errMsg := fmt.Sprintf("Jumpcloud error: %s", jcmsg.Message)
			return samlAssertion, errors.Wrap(err, errMsg)
		}

		res, err = jc.verifyMFA(authSubmitURL, loginDetails, a, messageBody, x.Token)
		if err != nil {
			return samlAssertion, err
		}
	}

	// Check if our auth was successful
	if res.StatusCode == 200 {
		// Grab the body from the response that has the redirect in it.
		reDirBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "Error reading body")
		}

		// Unmarshall the body to get the redirect address
		var jcrd = new(JCRedirect)
		err = json.Unmarshal(reDirBody, &jcrd)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "Error unmarshalling redirectTo response!")
		}

		// Send the final GET for our SAML response
		res, err = jc.client.Get(jcrd.Address)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error submitting request for SAML value")
		}
		//try to extract SAMLResponse
		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error parsing document")
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

		res.Body.Close()
	} else {
		errMsg := fmt.Sprintf("error when trying to auth, status code %d", res.StatusCode)
		return samlAssertion, errors.Wrap(err, errMsg)
	}

	return samlAssertion, nil
}

func (jc *Client) verifyMFA(jumpCloudOrgHost string, loginDetails *creds.LoginDetails, a AuthRequest, body []byte, xsrfToken string) (*http.Response, error) {
	// Get the user's MFA token and re-build the body

	option, err := jc.getUserOption(body)
	if err != nil {
		return nil, err
	}
	// make sure we set chosen option here
	jc.mfa = option

	switch option {
	case IdentifierTotpMfa:
		// Re-request with our OTP
		a.OTP = loginDetails.MFAToken
		if a.OTP == "" {
			a.OTP = prompter.StringRequired("MFA Token")
		}
		authBody, err := json.Marshal(a)
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication req body after getting MFA Token")
		}

		req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(string(authBody)))
		if err != nil {
			return nil, errors.Wrap(err, "error building MFA authentication request")
		}

		// Re-add the necessary headers to our remade auth request
		req.Header.Add("X-Xsrftoken", xsrfToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Resubmit
		return jc.client.Do(req)
	case IdentifierU2F:
		res, err := jc.client.Get(webauthnSubmitURL)
		if err != nil {
			return nil, errors.Wrap(err, "error submitting request for SAML value")
		}
		defer res.Body.Close()

		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		respStr := string(respBody)

		challenge := gjson.Get(respStr, "publicKey.challenge").String()
		allowCreds := gjson.Get(respStr, "publicKey.allowCredentials").Array()
		if len(allowCreds) < 1 {
			return nil, errors.New("unsupported case, we expect publicKey to be an array of at least one element")
		}
		credsMap := allowCreds[0].Map()
		key, ok := credsMap["id"]
		if !ok {
			return nil, errors.New("can't find key handle or key id in the allowed credentials map")
		}

		fidoClient, err := NewFidoClient(
			challenge,
			gjson.Get(respStr, "publicKey.rpId").String(),
			key.String(),
			gjson.Get(respStr, "token").String(),
			new(U2FDeviceFinder),
		)
		if err != nil {
			return nil, err
		}

		signedAssertion, err := fidoClient.ChallengeU2F()
		if err != nil {
			return nil, err
		}

		payload, err := json.Marshal(signedAssertion)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("POST", webauthnSubmitURL, strings.NewReader(string(payload)))
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("X-Xsrftoken", xsrfToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		return jc.client.Do(req)
	case IdentifierDuoMfa:
		// Get Duo config
		req, err := http.NewRequest("GET", duoAuthSubmitURL, nil)
		if err != nil {
			return nil, errors.Wrap(err, "error building MFA authentication request")
		}
		// Re-add the necessary headers to our remade auth request
		req.Header.Add("X-Xsrftoken", xsrfToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		res, err := jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving Duo configuration")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, errors.New("error retrieving Duo configuration, non 200 status returned")
		}
		duoResp, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving Duo configuration")
		}
		duoHost := gjson.GetBytes(duoResp, "api_host").String()
		duoSignature := gjson.GetBytes(duoResp, "sig_request").String()
		duoSignatures := strings.Split(duoSignature, ":")
		duoToken := gjson.GetBytes(duoResp, "token").String()

		duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

		duoForm := url.Values{}
		duoForm.Add("parent", "https://console.jumpcloud.com/duo2fa")
		duoForm.Add("java_version", "")
		duoForm.Add("java_version", "")
		duoForm.Add("flash_version", "")
		duoForm.Add("screen_resolution_width", "3008")
		duoForm.Add("screen_resolution_height", "1692")
		duoForm.Add("color_depth", "24")

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication request")
		}
		q := req.URL.Query()
		q.Add("tx", duoSignatures[0])
		req.URL.RawQuery = q.Encode()

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving verify response")
		}
		defer res.Body.Close()

		//try to extract sid
		doc, err := goquery.NewDocumentFromReader(res.Body)
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
			return nil, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving verify response")
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving body from response")
		}

		resp := string(body)

		duoTxStat := gjson.Get(resp, "stat").String()
		duoTxID := gjson.Get(resp, "response.txid").String()
		if duoTxStat != "OK" {
			return nil, errors.Wrap(err, "error authenticating mfa device")
		}

		// get duo cookie
		duoSubmitURL = fmt.Sprintf("https://%s/frame/status", duoHost)

		duoForm = url.Values{}
		duoForm.Add("sid", duoSID)
		duoForm.Add("txid", duoTxID)

		req, err = http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving verify response")
		}
		defer res.Body.Close()

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving body from response")
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
					return nil, errors.Wrap(err, "error building authentication request")
				}

				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				res, err = jc.client.Do(req)
				if err != nil {
					return nil, errors.Wrap(err, "error retrieving verify response")
				}
				defer res.Body.Close()

				body, err = ioutil.ReadAll(res.Body)
				if err != nil {
					return nil, errors.Wrap(err, "error retrieving body from response")
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
					return nil, errors.Wrap(err, "failed to authenticate device")
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
			return nil, errors.Wrap(err, "error constructing request object to result url")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving duo result response")
		}
		defer res.Body.Close()

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "duoResultSubmit: error retrieving body from response")
		}

		resp = string(body)

		duoTxStat = gjson.Get(resp, "stat").String()
		if duoTxStat != "OK" {
			message := gjson.Get(resp, "message").String()
			return nil, fmt.Errorf("duoResultSubmit: %s %s", duoTxStat, message)
		}

		duoTxCookie := gjson.Get(resp, "response.cookie").String()
		if duoTxCookie == "" {
			return nil, errors.New("duoResultSubmit: Unable to get response.cookie")
		}

		jumpCloudJsonPayload := []byte(
			fmt.Sprintf(`{"token":"%s","sig_response":"%s"}`,
				duoToken,
				fmt.Sprintf("%s:%s", duoTxCookie, duoSignatures[1])),
		)

		req, err = http.NewRequest("POST", duoAuthSubmitURL, bytes.NewBuffer(jumpCloudJsonPayload))
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("X-Xsrftoken", xsrfToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		return jc.client.Do(req)
	}

	return &http.Response{}, errors.New("no MFA method provided")
}

func (jc *Client) getUserOption(body []byte) (string, error) {
	// data =>map[factors:[map[status:available type:totp] map[status:available type:webauthn]] message:MFA required.]
	mfaConfigData := gjson.GetBytes(body, "factors")
	if mfaConfigData.Index == 0 {
		log.Fatalln("Mfa Config option not found")
		return "", errors.New("Mfa not configured")
	}
	var mfaOptionsAvailableAtJumpCloud []string
	var mfaDisplayOptions []string

	for _, option := range mfaConfigData.Array() {
		if option.Get("status").String() == "available" {
			identifier := option.Get("type").String()
			if _, ok := supportedMfaOptions[identifier]; ok {
				// check if the option is supported and among jumpcloud options
				if jc.mfa != "Auto" {
					if strings.ToLower(jc.mfa) == identifier {
						return identifier, nil
					}
				}
				mfaOptionsAvailableAtJumpCloud = append(mfaOptionsAvailableAtJumpCloud, identifier)
				mfaDisplayOptions = append(mfaDisplayOptions, supportedMfaOptions[identifier])
			}
		}
	}
	if len(mfaOptionsAvailableAtJumpCloud) == 0 {
		return "", errors.New("No MFA options available")
	} else if len(mfaOptionsAvailableAtJumpCloud) == 1 {
		return mfaOptionsAvailableAtJumpCloud[0], nil
	}

	mfaOption := prompter.Choose("Select which MFA option to use", mfaDisplayOptions)
	return mfaOptionsAvailableAtJumpCloud[mfaOption], nil
}
