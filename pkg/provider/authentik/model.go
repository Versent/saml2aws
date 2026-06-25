package authentik

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

type authentikContext struct {
	loginDetails *creds.LoginDetails
	// url is the current position in the authentik flow. It is kept separate
	// from loginDetails.URL so that the original entry URL is preserved for the
	// caller (e.g. credential storage and the SAML cache key).
	url          string
	samlResponse string
}

type authentikPayload struct {
	Attrs            map[string]string
	Component        string
	Type             string
	HasPasswordField bool                           `json:"password_fields"`
	RedirectTo       string                         `json:"to"`
	Errors           map[string][]map[string]string `json:"response_errors"`
	DeviceChallenges []deviceChallenge              `json:"device_challenges"`
}

// deviceChallenge is a single entry of the authenticator-validate stage's
// device_challenges array. The challenge payload is device-class specific, so it
// is kept raw until the device class is known.
type deviceChallenge struct {
	DeviceClass string          `json:"device_class"`
	DeviceUID   string          `json:"device_uid"`
	Challenge   json.RawMessage `json:"challenge"`
}

// webAuthnRequestOptions mirrors the PublicKeyCredentialRequestOptions that
// authentik embeds in a webauthn device challenge. All binary values are
// base64url encoded.
type webAuthnRequestOptions struct {
	Challenge        string                         `json:"challenge"`
	RpID             string                         `json:"rpId"`
	Timeout          int                            `json:"timeout"`
	UserVerification string                         `json:"userVerification"`
	AllowCredentials []webAuthnCredentialDescriptor `json:"allowCredentials"`
}

type webAuthnCredentialDescriptor struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports"`
}

// webAuthnChallenge returns the parsed webauthn request options if the payload
// offers a webauthn device, or nil when none is present.
func (payload *authentikPayload) webAuthnChallenge() (*webAuthnRequestOptions, error) {
	for _, dc := range payload.DeviceChallenges {
		if dc.DeviceClass != "webauthn" {
			continue
		}
		var opts webAuthnRequestOptions
		if err := json.Unmarshal(dc.Challenge, &opts); err != nil {
			return nil, errors.Wrap(err, "error parsing webauthn challenge")
		}
		return &opts, nil
	}
	return nil, nil
}

func (ctx *authentikContext) updateURL(s string) error {
	if strings.Index(s, "/") == 0 {
		u, err := url.Parse(ctx.url)
		if err != nil {
			return errors.New("Invalid url")
		}
		s = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, s)
	}

	ctx.url = s
	return nil
}

func (ctx *authentikContext) setSAMLResponse(val string) {
	ctx.samlResponse = val
}

func (payload *authentikPayload) isTypeNative() bool {
	return payload.Type == "native"
}

func (payload *authentikPayload) isTypeRedirect() bool {
	return payload.Type == "redirect"
}

func (payload *authentikPayload) isTypeEmpty() bool {
	return payload.Type == ""
}

func (payload *authentikPayload) isComponentStageAutosubmit() bool {
	return payload.Component == "ak-stage-autosubmit"
}

func (payload *authentikPayload) isComponentFlowRedirect() bool {
	return payload.Component == "xak-flow-redirect"
}
