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
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

const (
	jcSSOBaseURL      = "https://sso.jumpcloud.com/"
	xsrfURL           = "https://console.jumpcloud.com/userconsole/xsrf"
	authSubmitURL     = "https://console.jumpcloud.com/userconsole/auth"
	duoAuthSubmitURL  = "https://console.jumpcloud.com/userconsole/auth/duo"
	IdentifierDuoMfa  = "duo"
	IdentifierTotpMfa = "totp"
)

var (
	supportedMfaOptions = map[string]MfaUserOption{
		IdentifierDuoMfa:  {"DUO MFA authentication", "duo"},
		IdentifierTotpMfa: {"TOTP MFA authentication", "totp"},
	}
)

type MfaUserOption struct {
	UserDisplayString string
	UserMfaOption     string
}

// Client is a wrapper representing a JumpCloud SAML client
type Client struct {
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

	// Check if we get a 401.  If we did, MFA is required and the OTP was not provided.
	// Get the OTP and resubmit.
	if res.StatusCode == 401 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving response from navigate request")
		}
		authStatus := gjson.GetBytes(body, "message").String()
		if authStatus == "MFA required." {
			res, err = verifyMfa(jc, authSubmitURL, loginDetails, a, body, x.Token)
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error verifying MFA")
			}
		} else {
			return samlAssertion, errors.New("failed to authenticate")
		}
	}

	// Check if our auth was successful
	if res.StatusCode == 200 {
		//try to extract SAMLResponse
		body, _ := ioutil.ReadAll(res.Body)
		doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(body))
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

	} else {
		errMsg := fmt.Sprintf("error when trying to auth, status code %d", res.StatusCode)
		return samlAssertion, errors.Wrap(err, errMsg)
	}

	return samlAssertion, nil
}

func verifyMfa(jc *Client, jumpcloudOrgHost string, loginDetails *creds.LoginDetails, a AuthRequest, body []byte, xsrfToken string) (*http.Response, error) {
	mfaConfigData := gjson.GetBytes(body, "factors")
	if mfaConfigData.Index == 0 {
		fmt.Println("Mfa Config option not found")
		return nil, errors.New("Mfa not configured ")
	}
	mfaOption := 0
	var mfaOptions []MfaUserOption
	for _, option := range mfaConfigData.Array() {
		if option.Get("status").String() == "available" {
			identifier := option.Get("type").String()
			if val, ok := supportedMfaOptions[identifier]; ok {
				mfaOptions = append(mfaOptions, val)
			}
		}
	}

	var mfaDisplayOptions []string
	var mfaUserOption string
	var mfaConfiguredSupported int

	if jc.mfa != "Auto" {
		mfaUserOption = strings.ToLower(jc.mfa)
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
			return nil, errors.New("unsupported mfa provider")
		}
	}

	if _, ok := supportedMfaOptions[mfaUserOption]; !ok {
		return nil, errors.New("unsupported mfa provider")
	}
	switch mfa := mfaUserOption; mfa {
	case IdentifierTotpMfa:
		// Get the user's MFA token and re-build the body
		a.OTP = loginDetails.MFAToken
		if a.OTP == "" {
			a.OTP = prompter.StringRequired("MFA Token")
		}

		authBody, err := json.Marshal(a)
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication req body after getting MFA Token")
		}

		// Re-request with our OTP
		req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(string(authBody)))
		if err != nil {
			return nil, errors.Wrap(err, "error building MFA authentication request")
		}
		// Re-add the necessary headers to our remade auth request
		req.Header.Add("X-Xsrftoken", xsrfToken)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Resubmit
		res, err := jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error submitting token")
		}

		// Grab the body from the response that has the redirect in it.
		reDirBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "Error reading body")
		}

		// Unmarshall the body to get the redirect address
		var jcrd = new(JCRedirect)
		err = json.Unmarshal(reDirBody, &jcrd)
		if err != nil {
			log.Fatalf("Error unmarshalling redirectTo response! %v", err)
		}

		// Send the final GET for our SAML response
		return jc.client.Get(jcrd.Address)
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

		//try to extract sid
		doc, err := goquery.NewDocumentFromResponse(res)
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

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving body from response")
		}

		resp = string(body)

		duoTxResult := gjson.Get(resp, "response.result").String()
		duoResultURL := gjson.Get(resp, "response.result_url").String()

		fmt.Println(gjson.Get(resp, "response.status").String())

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

				body, err = ioutil.ReadAll(res.Body)
				if err != nil {
					return nil, errors.Wrap(err, "error retrieving body from response")
				}

				resp := string(body)

				duoTxResult = gjson.Get(resp, "response.result").String()
				duoResultURL = gjson.Get(resp, "response.result_url").String()

				fmt.Println(gjson.Get(resp, "response.status").String())

				if duoTxResult == "FAILURE" {
					return nil, errors.Wrap(err, "failed to authenticate device")
				}

				if duoTxResult == "SUCCESS" {
					break
				}
			}
		}

		duoRequestURL := fmt.Sprintf("https://%s%s", duoHost, duoResultURL)
		req, err = http.NewRequest("POST", duoRequestURL, strings.NewReader(duoForm.Encode()))
		if err != nil {
			return nil, errors.Wrap(err, "error constructing request object to result url")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving duo result response")
		}

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, errors.Wrap(err, "duoResultSubmit: error retrieving body from response")
		}

		resp = string(body)
		duoTxCookie := gjson.Get(resp, "response.cookie").String()
		if duoTxCookie == "" {
			return nil, errors.Wrap(err, "duoResultSubmit: Unable to get response.cookie")
		}

		// callback to Jumpcloud with cookie
		jumpcloudForm := url.Values{}
		jumpcloudForm.Add("context", "sso")
		jumpcloudForm.Add("redirect_to", a.RedirectTo)
		jumpcloudForm.Add("token", duoToken)
		jumpcloudForm.Add("sig_response", fmt.Sprintf("%s:%s", duoTxCookie, duoSignatures[1]))

		req, err = http.NewRequest("POST", duoAuthSubmitURL, strings.NewReader(jumpcloudForm.Encode()))
		if err != nil {
			return nil, errors.Wrap(err, "error building authentication request")
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		return jc.client.Do(req)
	}
	return nil, errors.New("no mfa options provided")
}
