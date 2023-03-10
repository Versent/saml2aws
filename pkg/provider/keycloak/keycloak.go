package keycloak

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/marshallbrekka/go-u2fhost"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
	"github.com/versent/saml2aws/v2/pkg/provider/okta"
)

// Client wrapper around KeyCloak.
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
}

type authContext struct {
	mfaToken                string
	authenticatorIndex      uint
	authenticatorIndexValid bool
}

// New create a new KeyCloakClient
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into KeyCloak and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	return kc.doAuthenticate(&authContext{loginDetails.MFAToken, 0, true}, loginDetails)
}

func (kc *Client) doAuthenticate(authCtx *authContext, loginDetails *creds.LoginDetails) (string, error) {
	authSubmitURL, authForm, err := kc.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form from idp")
	}

	data, err := kc.postLoginForm(authSubmitURL, authForm)
	if err != nil {
		return "", fmt.Errorf("error submitting login form")
	}
	if authSubmitURL == "" {
		return "", fmt.Errorf("error submitting login form")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	if containsTotpForm(doc) {
		totpSubmitURL, err := extractSubmitURL(doc)
		if err != nil {
			return "", errors.Wrap(err, "unable to locate IDP totp form submit URL")
		}

		doc, err = kc.postTotpForm(authCtx, totpSubmitURL, doc)
		if err != nil {
			return "", errors.Wrap(err, "error posting totp form")
		}
	} else if containsWebauthnForm(doc) {
		credentialIDs, challenge, rpId, err := extractWebauthnParameters(doc)
		if err != nil {
			return "", errors.Wrap(err, "could not extract Webauthn parameters")
		}

		webauthnSubmitURL, err := extractSubmitURL(doc)
		if err != nil {
			return "", errors.Wrap(err, "unable to locate IDP Webauthn form submit URL")
		}

		doc, err = kc.postWebauthnForm(webauthnSubmitURL, credentialIDs, challenge, rpId)
		if err != nil {
			return "", errors.Wrap(err, "error posting Webauthn form")
		}
	}

	samlResponse, err := extractSamlResponse(doc)
	if err != nil && authCtx.authenticatorIndexValid && passwordValid(doc) {
		return kc.doAuthenticate(authCtx, loginDetails)
	}
	return samlResponse, err
}

func extractWebauthnParameters(doc *goquery.Document) (credentialIDs []string, challenge string, rpID string, err error) {
	doc.Find("input[name=authn_use_chk]").Each(func(i int, s *goquery.Selection) {
		value, ok := s.Attr("value")
		if !ok {
			return
		}
		credentialIDs = append(credentialIDs, value)
	})
	if len(credentialIDs) == 0 {
		return nil, "", "", errors.New("no credentialID found on page")
	}

	challengeRE, err := regexp.Compile(`let challenge = "(.+)";`)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not compile regular expression")
	}

	rpIDRE, err := regexp.Compile(`let rpId = "(.+)"`)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not compile regular expression")
	}
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		content := s.Text()
		challengeSubmatch := challengeRE.FindStringSubmatch(content)
		if challengeSubmatch == nil {
			return
		}
		challenge = challengeSubmatch[1]
		rpIDSubmatch := rpIDRE.FindStringSubmatch(content)
		if rpIDSubmatch == nil {
			return
		}
		rpID = rpIDSubmatch[1]
	})
	return credentialIDs, challenge, rpID, nil
}

func (kc *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	res, err := kc.client.Get(loginDetails.URL)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build document from response")
	}

	if res.StatusCode == http.StatusUnauthorized {
		authSubmitURL, err := extractSubmitURL(doc)
		if err != nil {
			return "", nil, errors.Wrap(err, "unable to locate IDP authentication form submit URL")
		}
		loginDetails.URL = authSubmitURL
		return kc.getLoginForm(loginDetails)
	}

	authForm := url.Values{}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateKeyCloakFormData(authForm, s, loginDetails)
	})

	authSubmitURL, err := extractSubmitURL(doc)
	if err != nil {
		return "", nil, errors.Wrap(err, "unable to locate IDP authentication form submit URL")
	}

	return authSubmitURL, authForm, nil
}

func (kc *Client) postLoginForm(authSubmitURL string, authForm url.Values) ([]byte, error) {

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body")
	}

	return data, nil
}

func (kc *Client) postTotpForm(authCtx *authContext, totpSubmitURL string, doc *goquery.Document) (*goquery.Document, error) {

	otpForm := url.Values{}

	if authCtx.mfaToken == "" {
		authCtx.mfaToken = prompter.RequestSecurityCode("000000")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateOTPFormData(authCtx, otpForm, s)
	})

	req, err := http.NewRequest("POST", totpSubmitURL, strings.NewReader(otpForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Check if the next authenticator is available
	authCtx.authenticatorIndex = authCtx.authenticatorIndex + 1
	nextAuthenticatorSelector := fmt.Sprintf("input#%s", generateAuthenticatorElementId(authCtx.authenticatorIndex))
	authCtx.authenticatorIndexValid = doc.Find(nextAuthenticatorSelector).Length() == 1

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving content")
	}

	doc, err = goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading totp form response")
	}

	return doc, nil
}

func (kc *Client) postWebauthnForm(webauthnSubmitURL string, credentialIDs []string, challenge, rpId string) (*goquery.Document, error) {
	webauthnForm := url.Values{}

	var assertion *okta.SignedAssertion
	var pickedCredentialID string
	for i, credentialID := range credentialIDs {
		fidoClient, err := okta.NewFidoClient(
			challenge,
			rpId,
			"",
			credentialID,
			"",
			new(okta.U2FDeviceFinder),
		)
		if err != nil {
			return nil, errors.Wrap(err, "error connecting to Webauthn device")
		}

		assertion, err = fidoClient.ChallengeU2F()
		if _, ok := err.(*u2fhost.BadKeyHandleError); ok && i < len(credentialIDs)-1 {
			log.Println("Device does not have key handle, trying next ...")
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "error while getting Webauthn challenge")
		}
		pickedCredentialID = credentialID
		break
	}
	if assertion == nil {
		return nil, errors.New("tried all Webauthn devices, none was recognized")
	}

	signature, err := reencodeAsURLEncoding(assertion.SignatureData)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected format for Webauthn signature data")
	}
	authenticatorData, err := reencodeAsURLEncoding(assertion.AuthenticatorData)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected format for Webauthn authenticator data")
	}
	webauthnForm.Set("clientDataJSON", assertion.ClientData)
	webauthnForm.Set("authenticatorData", authenticatorData)
	webauthnForm.Set("signature", signature)
	webauthnForm.Set("credentialId", pickedCredentialID)
	webauthnForm.Set("userHandle", "")
	webauthnForm.Set("error", "")

	req, err := http.NewRequest("POST", webauthnSubmitURL, strings.NewReader(webauthnForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving content")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error reading webauthn form response")
	}

	return doc, nil
}

func reencodeAsURLEncoding(data string) (string, error) {
	decodedSignature, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.Wrap(err, "invalid base64 encoding")
	}
	return base64.RawURLEncoding.EncodeToString(decodedSignature), nil
}

func extractSubmitURL(doc *goquery.Document) (string, error) {

	var submitURL string

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		submitURL = action
	})

	if submitURL == "" {
		return "", fmt.Errorf("unable to locate form submit URL")
	}

	return submitURL, nil
}

func extractSamlResponse(doc *goquery.Document) (string, error) {
	var samlAssertion = ""
	var err = fmt.Errorf("unable to locate saml response field")

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if ok && name == "SAMLResponse" {
			val, ok := s.Attr("value")
			if !ok {
				err = fmt.Errorf("unable to locate saml assertion value")
				return
			}
			err = nil
			samlAssertion = val
		}
	})
	return samlAssertion, err
}

func passwordValid(doc *goquery.Document) bool {
	var valid = true
	doc.Find("span#input-error").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if strings.Contains(text, "Invalid username or password.") {
			valid = false
			return
		}
	})
	return valid
}

func containsTotpForm(doc *goquery.Document) bool {
	// search totp field at Keycloak < 8.0.1
	totpIndex := doc.Find("input#totp").Index()

	if totpIndex != -1 {
		return true
	}

	// search otp field at Keycloak >= 8.0.1
	totpIndex = doc.Find("input#otp").Index()

	return totpIndex != -1
}

func containsWebauthnForm(doc *goquery.Document) bool {
	return doc.Find("form#webauth").Index() != -1
}

func updateKeyCloakFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	// log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "username") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "password") {
		authForm.Add(name, user.Password)
	} else {
		// pass through any hidden fields
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		authForm.Add(name, val)
	}
}

func updateOTPFormData(authCtx *authContext, otpForm url.Values, s *goquery.Selection) {
	name, ok := s.Attr("name")
	// log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}

	lname := strings.ToLower(name)
	// search otp field at Keycloak >= 8.0.1
	if strings.Contains(lname, "totp") {
		otpForm.Add(name, authCtx.mfaToken)
	} else if strings.Contains(lname, "otp") {
		otpForm.Add(name, authCtx.mfaToken)
	} else if strings.Contains(lname, "selectedcredentialid") {
		id, ok := s.Attr("id")
		if ok && id == generateAuthenticatorElementId(authCtx.authenticatorIndex) {
			val, ok := s.Attr("value")
			if ok {
				otpForm.Add(name, val)
			}
		}
	}

}

func generateAuthenticatorElementId(authenticatorIndex uint) string {
	return fmt.Sprintf("kc-otp-credential-%d", authenticatorIndex)
}
