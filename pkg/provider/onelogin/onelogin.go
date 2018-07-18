package onelogin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

// MFA identifier constants.
const (
	IdentifierOneLoginProtectMfa = "OneLogin Protect"
	IdentifierSmsMfa             = "OneLogin SMS"
	IdentifierTotpMfa            = "Google Authenticator"

	MessageMFARequired = "MFA is required for this user"
	MessageSuccess     = "Success"
	TypePending        = "pending"
	TypeSuccess        = "success"
)

// ProviderName constant holds the name of the OneLogin IDP.
const ProviderName = "OneLogin"

var logger = logrus.WithField("provider", ProviderName)

var (
	supportedMfaOptions = map[string]string{
		IdentifierOneLoginProtectMfa: "OLP MFA authentication",
		IdentifierSmsMfa:             "SMS MFA authentication",
		IdentifierTotpMfa:            "TOTP MFA authentication",
	}
)

// Client is a wrapper representing a OneLogin SAML client.
type Client struct {
	// AppID represents the OneLogin connector id.
	AppID string
	// Client is the HTTP client for accessing the IDP provider's APIs.
	Client *provider.HTTPClient
	// Subdomain is the organisation subdomain in OneLogin.
	Subdomain string
}

// AuthRequest represents an mfa OneLogin request.
type AuthRequest struct {
	AppID     string `json:"app_id"`
	Password  string `json:"password"`
	Subdomain string `json:"subdomain"`
	Username  string `json:"username_or_email"`
	IPAddress string `json:"ip_address,omitempty"`
}

// VerifyRequest represents an mfa verify request
type VerifyRequest struct {
	AppID      string `json:"app_id"`
	DeviceID   string `json:"device_id"`
	OTPToken   string `json:"otp_token,omitempty"`
	StateToken string `json:"state_token"`
}

// New creates a new OneLogin client.
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)
	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}
	// Assign a response validator to ensure all responses are either success or a redirect.
	// This is to avoid have explicit checks for every single response.
	client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator
	return &Client{AppID: idpAccount.AppID, Client: client, Subdomain: idpAccount.Subdomain}, nil
}

// Authenticate logs into OneLogin and returns a SAML response.
func (c *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	providerURL, err := url.Parse(loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error building providerURL")
	}
	host := providerURL.Host

	logger.Debug("Generating OneLogin access token")
	// request oAuth token required for working with OneLogin APIs
	oauthToken, err := generateToken(c, loginDetails, host)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate oauth token")
	}

	logger.Debug("Retrieved OneLogin OAuth token:", oauthToken)

	authReq := AuthRequest{Username: loginDetails.Username, Password: loginDetails.Password, AppID: c.AppID, Subdomain: c.Subdomain}
	var authBody bytes.Buffer
	err = json.NewEncoder(&authBody).Encode(authReq)
	if err != nil {
		return "", errors.Wrap(err, "error encoding authreq")
	}

	authSubmitURL := fmt.Sprintf("https://%s/api/1/saml_assertion", host)

	req, err := http.NewRequest("POST", authSubmitURL, &authBody)
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	addContentHeaders(req)
	addAuthHeader(req, oauthToken)

	logger.Debug("Requesting SAML Assertion")

	// request the SAML assertion. For more details check https://developers.onelogin.com/api-docs/1/saml-assertions/generate-saml-assertion
	res, err := c.Client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving auth response")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}

	resp := string(body)

	logger.Debug("SAML Assertion response code:", res.StatusCode)
	logger.Debug("SAML Assertion response body:", resp)

	authError := gjson.Get(resp, "status.error").Bool()
	authMessage := gjson.Get(resp, "status.message").String()
	authType := gjson.Get(resp, "status.type").String()
	if authError || authType != TypeSuccess {
		return "", errors.New(authMessage)
	}

	authData := gjson.Get(resp, "data")
	var samlAssertion string
	switch authMessage {
	// MFA not required
	case MessageSuccess:
		if authData.IsArray() {
			return "", errors.New("invalid SAML assertion returned")
		}
		samlAssertion = authData.String()
	case MessageMFARequired:
		if !authData.IsArray() {
			return "", errors.New("invalid MFA data returned")
		}
		logger.Debug("Verifying MFA")
		samlAssertion, err = verifyMFA(c, oauthToken, c.AppID, resp)
		if err != nil {
			return "", errors.Wrap(err, "error verifying MFA")
		}
	default:
		return "", errors.New("unexpected SAML assertion response")
	}

	return samlAssertion, nil
}

// generateToken is used to generate access token for all OneLogin APIs.
// For more infor read https://developers.onelogin.com/api-docs/1/oauth20-tokens/generate-tokens-2
func generateToken(oc *Client, loginDetails *creds.LoginDetails, host string) (string, error) {
	oauthTokenURL := fmt.Sprintf("https://%s/auth/oauth2/v2/token", host)

	req, err := http.NewRequest("POST", oauthTokenURL, strings.NewReader(`{"grant_type":"client_credentials"}`))
	if err != nil {
		return "", errors.Wrap(err, "error building oauth token request")
	}

	addContentHeaders(req)
	req.SetBasicAuth(loginDetails.ClientID, loginDetails.ClientSecret)

	res, err := oc.Client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving oauth token response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error reading oauth token response")
	}
	defer res.Body.Close()

	return gjson.Get(string(body), "access_token").String(), nil
}

func addAuthHeader(r *http.Request, oauthToken string) {
	r.Header.Add("Authorization", "bearer: "+oauthToken)
}

func addContentHeaders(r *http.Request) {
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Accept", "application/json")
}

// verifyMFA is used to either prompt to user for one time password or request approval using push notification.
// For more details check https://developers.onelogin.com/api-docs/1/saml-assertions/verify-factor
func verifyMFA(oc *Client, oauthToken, appID, resp string) (string, error) {
	stateToken := gjson.Get(resp, "data.0.state_token").String()
	// choose an mfa option if there are multiple enabled
	var option int
	var mfaOptions []string
	for _, id := range gjson.Get(resp, "data.0.devices.#.device_type").Array() {
		identifier := id.String()
		if val, ok := supportedMfaOptions[identifier]; ok {
			mfaOptions = append(mfaOptions, val)
		} else {
			mfaOptions = append(mfaOptions, "UNSUPPORTED: "+identifier)
		}
	}
	if len(mfaOptions) > 1 {
		option = prompter.Choose("Select which MFA option to use", mfaOptions)
	}

	factorID := gjson.Get(resp, fmt.Sprintf("data.0.devices.%d.device_id", option)).String()
	callbackURL := gjson.Get(resp, "data.0.callback_url").String()
	mfaIdentifer := gjson.Get(resp, fmt.Sprintf("data.0.devices.%d.device_type", option)).String()
	mfaDeviceID := gjson.Get(resp, fmt.Sprintf("data.0.devices.%d.device_id", option)).String()

	logger.WithField("factorID", factorID).WithField("callbackURL", callbackURL).WithField("mfaIdentifer", mfaIdentifer).Debug("MFA")

	if _, ok := supportedMfaOptions[mfaIdentifer]; !ok {
		return "", errors.New("unsupported mfa provider")
	}

	// get signature & callback
	verifyReq := VerifyRequest{AppID: appID, DeviceID: mfaDeviceID, StateToken: stateToken}
	verifyBody := new(bytes.Buffer)
	err := json.NewEncoder(verifyBody).Encode(verifyReq)
	if err != nil {
		return "", errors.Wrap(err, "error encoding verifyReq")
	}

	req, err := http.NewRequest("POST", callbackURL, verifyBody)
	if err != nil {
		return "", errors.Wrap(err, "error building verify request")
	}

	addContentHeaders(req)
	addAuthHeader(req, oauthToken)

	res, err := oc.Client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving verify response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}
	resp = string(body)

	switch mfa := mfaIdentifer; mfa {
	case IdentifierSmsMfa, IdentifierTotpMfa:
		verifyCode := prompter.StringRequired("Enter verification code")
		tokenReq := VerifyRequest{AppID: appID, DeviceID: mfaDeviceID, StateToken: stateToken, OTPToken: verifyCode}
		tokenBody := new(bytes.Buffer)
		json.NewEncoder(tokenBody).Encode(tokenReq)

		req, err = http.NewRequest("POST", callbackURL, tokenBody)
		if err != nil {
			return "", errors.Wrap(err, "error building token post request")
		}

		addContentHeaders(req)
		addAuthHeader(req, oauthToken)

		res, err := oc.Client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving token post response")
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving body from response")
		}

		resp = string(body)

		return gjson.Get(resp, "data").String(), nil

	case IdentifierOneLoginProtectMfa:
		fmt.Printf("\nWaiting for approval, please check your OneLogin Protect app ...")

		started := time.Now()
		// loop until success, error, or timeout
		for {
			if time.Since(started) > time.Minute {
				fmt.Println(" Timeout")
				return "", errors.New("User did not accept MFA in time")
			}

			logger.Debug("Verifying with OneLogin Protect")
			res, err = oc.Client.Do(req)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving verify response")
			}

			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return "", errors.Wrap(err, "error retrieving body from response")
			}

			message := gjson.Get(string(body), "status.message").String()

			// on 'error' status
			if gjson.Get(string(body), "status.error").Bool() {
				return "", errors.New(message)
			}

			switch gjson.Get(string(body), "status.type").String() {
			case TypePending:
				time.Sleep(time.Second)
				fmt.Printf(".")

			case TypeSuccess:
				fmt.Println(" Approved")
				return gjson.Get(string(body), "data").String(), nil

			default:
				fmt.Println(" Error:")
				return "", errors.New("unsupported response from OneLogin, please raise ticket with saml2aws")
			}
		}
	}

	// catch all
	return "", errors.New("no mfa options provided")
}
