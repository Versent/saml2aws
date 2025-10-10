package authentik

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

type authentikContext struct {
	loginDetails *creds.LoginDetails
	samlResponse string
}

type authentikPayload struct {
	Attrs            map[string]string
	Component        string
	Type             string
	HasPasswordField bool                           `json:"password_fields"`
	RedirectTo       string                         `json:"to"`
	Errors           map[string][]map[string]string `json:"response_errors"`
}

func (ctx *authentikContext) updateURL(s string) error {
	if strings.Index(s, "/") == 0 {
		u, err := url.Parse(ctx.loginDetails.URL)
		if err != nil {
			return errors.New("Invalid url")
		}
		s = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, s)
	}

	ctx.loginDetails.URL = s
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
