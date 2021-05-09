package auth0

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

const (
	connectionInfoJSURLFmt = "https://cdn.auth0.com/client/%s.js"
	authOriginURLFmt       = "https://%s.auth0.com"
	authSubmitURLFmt       = "https://%s.auth0.com/usernamepassword/login"
)

var (
	authURLPattern        = regexp.MustCompile(`https://([^.]+)\.auth0\.com/samlp/(.+)`)
	connectionInfoPattern = regexp.MustCompile(`Auth0\.setClient\((.*)\)`)
	sessionInfoPattern    = regexp.MustCompile(`window\.atob\('(.*)'\)`)

	defaultPrompter = prompter.NewCli()
)

// Client wrapper around Auth0.
type Client struct {
	provider.ValidateBase
	client *provider.HTTPClient
}

// authInfo represents Auth0 first auth request
type authInfo struct {
	clientID             string
	tenant               string
	connection           string
	state                string
	csrf                 string
	connectionInfoURLFmt string
	authOriginURLFmt     string
	authSubmitURLFmt     string
}

// authRequest represents Auth0 request
type authRequest struct {
	ClientID     string      `json:"client_id"`
	Connection   string      `json:"connection"`
	Password     string      `json:"password"`
	PopupOptions interface{} `json:"popup_options"`
	Protocol     string      `json:"protocol"`
	RedirectURI  string      `json:"redirect_uri"`
	ResponseType string      `json:"response_type"`
	Scope        string      `json:"scope"`
	SSO          bool        `json:"sso"`
	State        string      `json:"state"`
	Tenant       string      `json:"tenant"`
	Username     string      `json:"username"`
	CSRF         string      `json:"_csrf"`
	Intstate     string      `json:"_intstate"`
}

// clientInfo represents Auth0 client information
type clientInfo struct {
	id         string
	tenantName string
}

// sessionInfo represents Auth0 session information
type sessionInfo struct {
	state string
	csrf  string
}

//authCallbackRequest represents Auth0 authentication callback request
type authCallbackRequest struct {
	method string
	url    string
	body   string
}

type authInfoOption func(*authInfo)

func defaultAuthInfoOptions() authInfoOption {
	return func(ai *authInfo) {
		ai.connectionInfoURLFmt = connectionInfoJSURLFmt
		ai.authOriginURLFmt = authOriginURLFmt
		ai.authSubmitURLFmt = authSubmitURLFmt
	}
}

// New create a new Auth0 Client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)
	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into Auth0 and returns a SAML response
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	authInfo, err := ac.buildAuthInfo(loginDetails.URL, defaultPrompter)
	if err != nil {
		return "", errors.Wrap(err, "error failed to build authentication info")
	}

	formHTML, err := ac.doLogin(loginDetails, authInfo)
	if err != nil {
		return "", errors.Wrap(err, "error failed to fetch SAML")
	}

	samlAssertion, err := mustFindInputByName(formHTML, "SAMLResponse")
	if err != nil {
		return "", errors.Wrap(err, "error failed to parse SAML")
	}

	return samlAssertion, nil
}

func (ac *Client) buildAuthInfo(
	loginURL string,
	prompter prompter.Prompter,
	opts ...authInfoOption,
) (*authInfo, error) {
	var ai authInfo
	if len(opts) == 0 {
		opts = []authInfoOption{defaultAuthInfoOptions()}
	}
	for _, opt := range opts {
		opt(&ai)
	}

	ci, err := extractClientInfo(loginURL)
	if err != nil {
		return nil, errors.Wrap(err, "error extractClientInfo")
	}

	connectionNames, err := ac.getConnectionNames(fmt.Sprintf(ai.connectionInfoURLFmt, ci.id))
	if err != nil {
		return nil, errors.Wrap(err, "error getConnectionNames")
	}

	var connection string
	switch {
	case len(connectionNames) == 0:
		return nil, errors.New("error connection name")
	case len(connectionNames) == 1:
		connection = connectionNames[0]
	default:
		index := prompter.Choose("Select connection", connectionNames)
		connection = connectionNames[index]
	}

	si, err := ac.fetchSessionInfo(loginURL)
	if err != nil {
		return nil, errors.Wrap(err, "error fetchSessionInfo")
	}

	ai.clientID = ci.id
	ai.tenant = ci.tenantName
	ai.connection = connection
	ai.state = si.state
	ai.csrf = si.csrf

	return &ai, nil
}

func (ac *Client) fetchSessionInfo(loginURL string) (*sessionInfo, error) {
	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error building request")
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving response")
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving response body")
	}
	defer resp.Body.Close()

	tokenEncoded := sessionInfoPattern.FindStringSubmatch(string(respBody))
	if len(tokenEncoded) < 1 {
		return nil, errors.New("error response doesn't match")
	}

	jsonByte, err := base64.StdEncoding.DecodeString(tokenEncoded[1])
	if err != nil {
		return nil, errors.Wrap(err, "error decoding matcher part by base64")
	}

	state := gjson.Get(string(jsonByte), "state").String()
	csrf := gjson.Get(string(jsonByte), "_csrf").String()
	if len(state) == 0 || len(csrf) == 0 {
		return nil, errors.New("error response doesn't include session info")
	}

	return &sessionInfo{
		state: state,
		csrf:  csrf,
	}, nil
}

func (ac *Client) getConnectionNames(connectionInfoURL string) ([]string, error) {
	req, err := http.NewRequest("GET", connectionInfoURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error building request")
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving response")
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body from response")
	}
	defer resp.Body.Close()

	match := connectionInfoPattern.FindStringSubmatch(string(respBody))
	if len(match) < 2 {
		return nil, errors.New("cannot find connection name")
	}

	var connectionNames []string
	result := gjson.Get(match[1], `strategies.#.connections.#.name`)
	for _, ary := range result.Array() {
		for _, name := range ary.Array() {
			connectionNames = append(connectionNames, name.String())
		}
	}

	return connectionNames, nil
}

func (ac *Client) doLogin(loginDetails *creds.LoginDetails, ai *authInfo) (string, error) {
	responseDoc, err := ac.loginAuth0(loginDetails, ai)
	if err != nil {
		return "", errors.Wrap(err, "error failed to login Auth0")
	}

	authCallback, err := parseResponseForm(responseDoc)
	if err != nil {
		return "", errors.Wrap(err, "error parse response document")
	}

	resp, err := ac.doAuthCallback(authCallback, ai)
	if err != nil {
		return "", errors.Wrap(err, "error failed to make callback")
	}

	return resp, nil
}

func (ac *Client) loginAuth0(loginDetails *creds.LoginDetails, ai *authInfo) (string, error) {
	authReq := authRequest{
		ClientID:     ai.clientID,
		Connection:   ai.connection,
		Password:     loginDetails.Password,
		PopupOptions: "{}",
		Protocol:     "samlp",
		RedirectURI:  "https://signin.aws.amazon.com/saml",
		ResponseType: "code",
		Scope:        "openid profile email",
		SSO:          true,
		State:        ai.state,
		Tenant:       ai.tenant,
		Username:     loginDetails.Username,
		CSRF:         ai.csrf,
		Intstate:     "deprecated",
	}

	authBody := new(bytes.Buffer)
	err := json.NewEncoder(authBody).Encode(authReq)
	if err != nil {
		return "", errors.Wrap(err, "error encoding authentication request")
	}

	authSubmitURL := fmt.Sprintf(ai.authSubmitURLFmt, ai.tenant)
	req, err := http.NewRequest("POST", authSubmitURL, authBody)
	if err != nil {
		return "", errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Origin", fmt.Sprintf(ai.authOriginURLFmt, ai.tenant))
	req.Header.Add(
		"Auth0-Client",
		base64.StdEncoding.EncodeToString(
			[]byte(`{"name":"lock.js","version":"11.11.0","lib_version":{"raw":"9.8.1"}}`),
		),
	)

	resp, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving auth response")
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}
	defer resp.Body.Close()

	return string(respBody), nil
}

func (ac *Client) doAuthCallback(authCallback *authCallbackRequest, ai *authInfo) (string, error) {
	req, err := http.NewRequest(authCallback.method, authCallback.url, strings.NewReader(authCallback.body))
	if err != nil {
		return "", errors.Wrap(err, "error building authentication callback request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", fmt.Sprintf(ai.authOriginURLFmt, ai.tenant))
	resp, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving auth callback response")
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from response")
	}
	defer resp.Body.Close()

	return string(respBody), nil
}

func extractClientInfo(url string) (*clientInfo, error) {
	matches := authURLPattern.FindStringSubmatch(url)
	if len(matches) < 3 {
		return nil, errors.New("error invalid Auth0 URL")
	}

	return &clientInfo{
		id:         matches[2],
		tenantName: matches[1],
	}, nil
}

func parseResponseForm(responseForm string) (*authCallbackRequest, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(responseForm))
	if err != nil {
		return nil, errors.Wrap(err, "error build goquery error")
	}

	form := doc.Find("form")
	methodDownCase, ok := form.Attr("method")
	if !ok {
		return nil, errors.New("invalid form method")
	}

	authCallbackURL, ok := form.Attr("action")
	if !ok {
		return nil, errors.New("invalid form action")
	}

	authCallBackForm := url.Values{}

	input := doc.Find("input")
	input.Each(func(_ int, selection *goquery.Selection) {
		name, nameOk := selection.Attr("name")
		value, valueOk := selection.Attr("value")

		if nameOk && valueOk {
			authCallBackForm.Add(name, html.UnescapeString(value))
		}
	})

	authCallbackBody := authCallBackForm.Encode()
	if len(authCallbackBody) == 0 {
		return nil, errors.New("invalid input values")
	}

	return &authCallbackRequest{
		method: strings.ToUpper(methodDownCase),
		url:    authCallbackURL,
		body:   authCallbackBody,
	}, nil
}

func mustFindInputByName(formHTML string, name string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(formHTML))
	if err != nil {
		return "", errors.Wrap(err, "error parse document")
	}

	var fieldValue string
	doc.Find(fmt.Sprintf(`input[name="%s"]`, name)).Each(
		func(i int, s *goquery.Selection) {
			val, _ := s.Attr("value")
			fieldValue = val
		},
	)
	if len(fieldValue) == 0 {
		return "", errors.New("error unable to get value")
	}

	return fieldValue, nil
}
