package authentik

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

// Client wrapper around authentik.
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
}

var logger = logrus.WithField("provider", "authentik")

// New create a new client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		client: client,
	}, nil
}

// Authenticate Log into authentik and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	ctx := &authentikContext{
		loginDetails: loginDetails,
	}
	samlResponse, err := kc.auth(ctx)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving saml response from idp")
	}

	return samlResponse, err
}

// auth Authentication
func (kc *Client) auth(ctx *authentikContext) (string, error) {
	logger.Debug("[GET] ", ctx.loginDetails.URL)
	res, err := kc.client.Get(ctx.loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving initial url")
	}
	if res.StatusCode == http.StatusFound {
		var location *url.URL
		location, err = res.Location()
		if err != nil {
			return "", err
		}
		err = ctx.updateURL(location.String())
		if err != nil {
			return "", err
		}

		return kc.auth(ctx)
	}

	requestURL := res.Request.URL
	if len(res.Cookies()) > 0 {
		baseURL := &url.URL{Scheme: requestURL.Scheme, Host: requestURL.Host, Path: "/"}
		kc.client.Jar.SetCookies(baseURL, res.Cookies())
	}

	next, err := kc.processQuery(ctx)
	if err != nil {
		return "", err
	}
	if ctx.samlResponse != "" {
		return ctx.samlResponse, nil
	}

	err = ctx.updateURL(next)
	if err != nil {
		return "", err
	}
	return kc.auth(ctx)
}

// processQuery Loop to get the authentik credentials
func (kc *Client) processQuery(ctx *authentikContext) (string, error) {
	var shouldContinue bool
	var next string
	var err error

	next, err = queryNextURL(ctx.loginDetails.URL)
	if err != nil {
		return "", err
	}
	err = ctx.updateURL(next)
	if err != nil {
		return "", err
	}

	for {
		shouldContinue, next, err = kc.queryNext(ctx)
		if err != nil {
			return "", err
		}
		if next != "" {
			err = ctx.updateURL(next)
			if err != nil {
				return "", err
			}
		}
		if !shouldContinue {
			break
		}
	}

	return next, nil
}

// queryNext Do query and submit infos
func (kc *Client) queryNext(ctx *authentikContext) (bool, string, error) {
	logger.Debug("[GET] ", ctx.loginDetails.URL)
	res, err := kc.client.Get(ctx.loginDetails.URL)
	if err != nil {
		return false, "", err
	}
	if res.StatusCode == http.StatusFound {
		next, err1 := res.Location()
		if err1 != nil {
			return false, "", err1
		}
		err = ctx.updateURL(next.String())
		if err != nil {
			return false, "", err
		}

		return kc.queryNext(ctx)
	}
	var payload *authentikPayload
	payload, err = parseResponsePayload(res)
	if err != nil {
		return false, "", err
	}

	if payload.isTypeRedirect() || payload.isComponentFlowRedirect() {
		// login success if there is a redirect
		logger.Debug("Login success, redirect to saml response")
		return false, payload.RedirectTo, nil
	} else if !payload.isTypeNative() && !payload.isTypeEmpty() {
		return false, "", errors.New("Unknown type: " + payload.Type)
	}

	if payload.isComponentStageAutosubmit() {
		ctx.setSAMLResponse(payload.Attrs["SAMLResponse"])
		return false, "", nil
	}

	next, err := kc.doPostQuery(ctx, payload)
	return true, next, err
}

// doPostQuery For all data setting operations
func (kc *Client) doPostQuery(ctx *authentikContext, payload *authentikPayload) (string, error) {
	data, err := getLoginJSON(ctx.loginDetails, payload)
	if err != nil {
		return "", err
	}

	logger.Debug("[POST]", ctx.loginDetails.URL)
	res, err := kc.client.Post(ctx.loginDetails.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if res.StatusCode == http.StatusOK {
		var payload *authentikPayload
		payload, err = parseResponsePayload(res)
		if err != nil {
			return "", err
		}

		var errMsg string
		if len(payload.Errors) > 0 {
			errMsg = prepareErrors(payload.Component, payload.Errors)
		} else {
			errMsg = "Unexpected"
		}

		return "", errors.New(errMsg)
	}
	loc, err := res.Location()
	return loc.String(), err
}

// getLoginJSON Generate the login json
func getLoginJSON(loginDetails *creds.LoginDetails, payload *authentikPayload) ([]byte, error) {
	component := payload.Component
	m := map[string]string{
		"component": component,
	}
	switch component {
	case "ak-stage-identification":
		m["uid_field"] = loginDetails.Username
		if payload.HasPassowrdField {
			m["password"] = loginDetails.Password
		}
	case "ak-stage-password":
		m["password"] = loginDetails.Password
	case "ak-stage-authenticator-validate":
		logger.Debugf("Debug - getLoginJSON data: %+v", m)
		if loginDetails.MFAToken == "" {
			loginDetails.MFAToken = prompter.RequestSecurityCode("000000")
		}
		m["code"] = loginDetails.MFAToken
	default:
		return []byte(""), errors.New("unknown component: " + component)
	}
	return json.Marshal(m)
}

// queryNextURL Get the next api url
func queryNextURL(u string) (string, error) {
	next, err := url.Parse(u)
	if err != nil {
		return "", errors.New("Invalid url")
	}

	result := strings.Split(next.Path, "/")
	flow := result[len(result)-2]
	return fmt.Sprintf("%s://%s/api/v3/flows/executor/%s/?query=%s", next.Scheme, next.Host, flow, url.QueryEscape(next.RawQuery)), nil
}

// getFieldName Get name of component
func getFieldName(component string) (string, error) {
	prefix := "ak-stage-"
	if strings.Index(component, prefix) != 0 {
		return "", errors.New("")
	}
	s := strings.Split(component, "ak-stage-")
	return s[len(s)-1], nil
}

// prepareErrors Transform errors to string
func prepareErrors(component string, errs map[string][]map[string]string) string {
	field, err := getFieldName(component)
	if err != nil {
		return "Invalid component"
	}

	key := "non_field_errors"
	if field == "password" {
		key = "password"
	}
	msgs := make([]string, 0, len(errs[key]))
	for _, err := range errs[key] {
		msgs = append(msgs, fmt.Sprintf("%s %s: %s", field, err["code"], err["string"]))
	}
	return strings.Join(msgs, "; ")
}

// parseResponsePayload Parse response from authentik api
func parseResponsePayload(res *http.Response) (*authentikPayload, error) {
	var payload authentikPayload
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil
}
