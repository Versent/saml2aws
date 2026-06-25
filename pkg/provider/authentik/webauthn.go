package authentik

import (
	"encoding/base64"
	"encoding/json"

	"github.com/marshallbrekka/go-u2fhost"
	"github.com/pkg/errors"

	"github.com/versent/saml2aws/v2/pkg/provider/okta"
)

// fidoAuthenticator performs a single WebAuthn (FIDO U2F) assertion against a
// hardware security key. It is abstracted behind an interface so that tests can
// inject a fake device without touching real USB hardware.
type fidoAuthenticator interface {
	challengeU2F(challenge, rpID, keyHandle string) (*okta.SignedAssertion, error)
}

// u2fAuthenticator is the production fidoAuthenticator. It reuses the shared FIDO
// client that the Okta and Keycloak providers rely on.
type u2fAuthenticator struct{}

func (u2fAuthenticator) challengeU2F(challenge, rpID, keyHandle string) (*okta.SignedAssertion, error) {
	// AppID == rpID makes the underlying client build the WebAuthn origin as
	// "https://"+rpID, which is exactly what authentik expects.
	fido, err := okta.NewFidoClient(challenge, rpID, "", keyHandle, "", new(okta.U2FDeviceFinder))
	if err != nil {
		return nil, err
	}
	return fido.ChallengeU2F()
}

// webAuthnAssertion is the body posted back to the authenticator-validate stage
// when answering with a security key. It mirrors the PublicKeyCredential the
// authentik web frontend submits.
type webAuthnAssertion struct {
	Component string             `json:"component"`
	WebAuthn  webAuthnCredential `json:"webauthn"`
}

type webAuthnCredential struct {
	ID       string                     `json:"id"`
	RawID    string                     `json:"rawId"`
	Type     string                     `json:"type"`
	Response webAuthnCredentialResponse `json:"response"`
}

type webAuthnCredentialResponse struct {
	ClientDataJSON    string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        *string `json:"userHandle"`
}

// signWebAuthnAssertion drives the hardware key for the given webauthn challenge
// and marshals the assertion into the POST body authentik expects.
func (kc *Client) signWebAuthnAssertion(component string, opts *webAuthnRequestOptions) ([]byte, error) {
	if len(opts.AllowCredentials) == 0 {
		return nil, errors.New("authentik webauthn challenge contains no credentials; " +
			"passwordless/resident keys are not supported by the U2F flow")
	}

	var assertion *okta.SignedAssertion
	var pickedID string
	for i, cred := range opts.AllowCredentials {
		a, err := kc.fido.challengeU2F(opts.Challenge, opts.RpID, cred.ID)
		if _, ok := err.(*u2fhost.BadKeyHandleError); ok && i < len(opts.AllowCredentials)-1 {
			logger.Debug("webauthn device does not have this key handle, trying next")
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "error performing webauthn assertion")
		}
		assertion = a
		pickedID = cred.ID
		break
	}
	if assertion == nil {
		return nil, errors.New("no registered webauthn device was recognized")
	}

	// The shared FIDO client returns clientDataJSON already base64url encoded, but
	// authenticatorData and signature in standard base64; authentik wants base64url.
	authenticatorData, err := urlEncode(assertion.AuthenticatorData)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected format for webauthn authenticator data")
	}
	signature, err := urlEncode(assertion.SignatureData)
	if err != nil {
		return nil, errors.Wrap(err, "unexpected format for webauthn signature data")
	}

	body := webAuthnAssertion{
		Component: component,
		WebAuthn: webAuthnCredential{
			ID:    pickedID,
			RawID: pickedID,
			Type:  "public-key",
			Response: webAuthnCredentialResponse{
				ClientDataJSON:    assertion.ClientData,
				AuthenticatorData: authenticatorData,
				Signature:         signature,
				UserHandle:        nil,
			},
		},
	}
	return json.Marshal(body)
}

// urlEncode re-encodes a standard base64 string as base64url without padding.
func urlEncode(stdEncodedStr string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(stdEncodedStr)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(decoded), nil
}
