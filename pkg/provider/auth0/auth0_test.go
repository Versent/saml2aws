package auth0

import (
	"encoding/base64"
	"fmt"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/versent/saml2aws/v2/pkg/provider"
)

const testSAMLFormHTMLFmt = `<html><head><title>test</title></head><body>
	<form method="post" name="hiddenform" action="%s">
	<input type="hidden" name="SAMLResponse" value="%s">
	<input type="hidden" name="RelayState" value="">
	<input type="submit" value="Submit">
	</form></body></html>`

func newTestProviderHTTPClientHelper(t *testing.T) *Client {
	t.Helper()

	tr := provider.NewDefaultTransport(false)
	httpClient, _ := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(&cfg.IDPAccount{}))
	httpClient.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	return &Client{
		ValidateBase: provider.ValidateBase{},
		client:       httpClient,
	}
}

func Test_defaultAuthInfoOptions(t *testing.T) {
	tests := []struct {
		name string
		want authInfo
	}{
		{
			name: "standard case",
			want: authInfo{
				connectionInfoURLFmt: connectionInfoJSURLFmt,
				authOriginURLFmt: authOriginURLFmt,
				authSubmitURLFmt: authSubmitURLFmt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got authInfo
			opts := defaultAuthInfoOptions()
			opts(&got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("defaultAuthInfoOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_fetchSessionInfo(t *testing.T) {
	type fields struct {
		mockServerHandlerFunc func(w http.ResponseWriter, r *http.Request)
	}
	tests := []struct {
		name    string
		fields  fields
		want    *sessionInfo
		wantErr bool
	}{
		{
			name: "standard case",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					jsonStr := `{"state": "StateToken", "_csrf": "CSRFToken"}`
					base64Encoded := base64.StdEncoding.EncodeToString([]byte(jsonStr))
					_, _ = w.Write([]byte(fmt.Sprintf(`window.atob('%s')`, base64Encoded)))
				},
			},
			want: &sessionInfo{
				state: "StateToken",
				csrf:  "CSRFToken",
			},
		},
		{
			name: "error case: server returns error",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			wantErr: true,
		},
		{
			name: "error case: server returns invalid response(not match)",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					jsonStr := `{"invalid": "response"}`
					base64Encoded := base64.StdEncoding.EncodeToString([]byte(jsonStr))
					_, _ = w.Write([]byte(fmt.Sprintf(`%s`, base64Encoded)))
				},
			},
			wantErr: true,
		},
		{
			name: "error case: server returns invalid response(not base64 encoded)",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					jsonStr := `{"invalid": "response"}`
					w.Write([]byte(fmt.Sprintf(`window.atob('%s')`, jsonStr)))
				},
			},
			wantErr: true,
		},
		{
			name: "error case: server returns invalid response(not value included)",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					jsonStr := `{"invalid": "response"}`
					base64Encoded := base64.StdEncoding.EncodeToString([]byte(jsonStr))
					w.Write([]byte(fmt.Sprintf(`window.atob('%s')`, base64Encoded)))
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(tt.fields.mockServerHandlerFunc))
			defer testServer.Close()

			ac := newTestProviderHTTPClientHelper(t)

			got, err := ac.fetchSessionInfo(testServer.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchSessionInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetchSessionInfo() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_getConnectionNames(t *testing.T) {
	type fields struct {
		mockServerHandlerFunc func(w http.ResponseWriter, r *http.Request)
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		wantErr bool
	}{
		{
			name: "standard case: single connection",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(
						`Auth0.setClient({"strategies":[{"name":"user_pool_name","connections":[` +
						`{"name":"connection-name1","display_name":"Connection name 1"}]}` +
						`]});`),
					)
				},
			},
			want: []string{
				"connection-name1",
			},
		},
		{
			name: "standard case: multiple connection",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(
						`Auth0.setClient({"strategies":[{"name":"user_pool_name","connections":[` +
							`{"name":"connection-name1","display_name":"Connection name 1"},` +
							`{"name":"connection-name2","display_name":"Connection name 2"}` +
							`]});`))
				},
			},
			want: []string{
				"connection-name1",
				"connection-name2",
			},
		},
		{
			name: "error case: server returns BadRequest",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			wantErr: true,
		},
		{
			name: "error case: invalid response format",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`invalid`))
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(tt.fields.mockServerHandlerFunc))
			defer testServer.Close()

			ac := newTestProviderHTTPClientHelper(t)

			got, err := ac.getConnectionNames(testServer.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("getConnectionNames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getConnectionNames() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_doLogin(t *testing.T) {
	type fields struct {
		mockServerHandlerFunc func(w http.ResponseWriter, r *http.Request)
	}
	type args struct {
		loginDetails *creds.LoginDetails
		ai     *authInfo
	}
	testArgs := args{
		loginDetails: &creds.LoginDetails{
			ClientID:     "clientID",
			ClientSecret: "clientSecret",
			Username:     "username",
			Password:     "password",
			MFAToken:     "mfaToken",
			DuoMFAOption: "duoMFAOption",
			URL:          "URL",
			StateToken:   "stateToken",
		},
		ai: &authInfo{
			clientID:   "clientID",
			tenant:     "tenant",
			connection: "connectionName",
			state:      "state",
			csrf:       "csrf",
		},
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "standard case",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					switch r.RequestURI {
					case "/tenant":
						callbackURL := "http://" + r.Host + r.RequestURI +  "/saml"
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(fmt.Sprintf(testSAMLFormHTMLFmt, callbackURL, "SAMLBase64Encoded")))
					case "/tenant/saml":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`response`))
					default:
						w.WriteHeader(http.StatusBadRequest)
					}
				},
			},
			args: testArgs,
			want: "response",
		},
		{
			name: "error case: loginAuth0 cause error",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			args: testArgs,
			wantErr: true,
		},
		{
			name: "error case: parseResponseForm cause error",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`invalid response for parseResponseForm`))
				},
			},
			args: testArgs,
			wantErr: true,
		},
		{
			name: "error case: doAuthCallback cause error",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					switch r.RequestURI {
					case "/tenant":
						callbackURL := "http://" + r.Host + r.RequestURI +  "/saml"
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(fmt.Sprintf(testSAMLFormHTMLFmt, callbackURL, "SAMLBase64Encoded")))
					default:
						w.WriteHeader(http.StatusBadRequest)
					}
				},
			},
			args: testArgs,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(tt.fields.mockServerHandlerFunc))
			defer testServer.Close()

			ac := newTestProviderHTTPClientHelper(t)
			tt.args.ai.authSubmitURLFmt = testServer.URL + "/%s"
			tt.args.ai.authOriginURLFmt = testServer.URL + "/%s"

			got, err := ac.doLogin(tt.args.loginDetails, tt.args.ai)
			if (err != nil) != tt.wantErr {
				t.Errorf("doLogin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("doLogin() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_loginAuth0(t *testing.T) {
	type fields struct {
		mockServerHandlerFunc func(w http.ResponseWriter, r *http.Request)
	}
	type args struct {
		loginDetails *creds.LoginDetails
		ai           *authInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "standard case",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`response`))
				},
			},
			args: args{
				loginDetails: &creds.LoginDetails{
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
					Username:     "username",
					Password:     "password",
					MFAToken:     "mfaToken",
					DuoMFAOption: "duoMFAOption",
					URL:          "URL",
					StateToken:   "stateToken",
				},
				ai: &authInfo{
					clientID:   "clientID",
					tenant:     "tenant",
					connection: "connectionName",
					state:      "state",
					csrf:       "csrf",
				},
			},
			want: "response",
		},
		{
			name: "error case: server returns BadRequest",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			args: args{
				loginDetails: &creds.LoginDetails{
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
					Username:     "username",
					Password:     "password",
					MFAToken:     "mfaToken",
					DuoMFAOption: "duoMFAOption",
					URL:          "URL",
					StateToken:   "stateToken",
				},
				ai: &authInfo{
					clientID:   "clientID",
					tenant:     "tenant",
					connection: "connectionName",
					state:      "state",
					csrf:       "csrf",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(tt.fields.mockServerHandlerFunc))
			defer testServer.Close()

			ac := newTestProviderHTTPClientHelper(t)
			tt.args.ai.authSubmitURLFmt = testServer.URL + "/%s"
			tt.args.ai.authOriginURLFmt = testServer.URL + "/%s"

			got, err := ac.loginAuth0(tt.args.loginDetails, tt.args.ai)
			if (err != nil) != tt.wantErr {
				t.Errorf("loginAuth0() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("loginAuth0() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_doAuthCallback(t *testing.T) {
	type fields struct {
		mockServerHandlerFunc func(w http.ResponseWriter, r *http.Request)
	}
	type args struct {
		authCallback *authCallbackRequest
		ai           *authInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "standard case",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("authCallbackResponse"))
				},
			},
			args: args{
				authCallback: &authCallbackRequest{
					method: "POST",
					body:   "RelayState=&SAMLResponse=SAMLBase64Encoded",
				},
				ai: &authInfo{
					tenant: "tenant",
				},
			},
			want: "authCallbackResponse",
		},
		{
			name: "error case: invalid HTTP method",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("authCallbackResponse"))
				},
			},
			args: args{
				authCallback: &authCallbackRequest{
					method: "無効", // means invalid in Japanese
					body:   "RelayState=&SAMLResponse=SAMLBase64Encoded",
				},
			},
			wantErr: true,
		},
		{
			name: "error case: server returns BadRequest",
			fields: fields{
				mockServerHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
				},
			},
			args: args{
				authCallback: &authCallbackRequest{
					method: "POST",
					body:   "RelayState=&SAMLResponse=SAMLBase64Encoded",
				},
				ai: &authInfo{
					tenant: "tenant",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(http.HandlerFunc(tt.fields.mockServerHandlerFunc))
			defer testServer.Close()

			ac := newTestProviderHTTPClientHelper(t)
			tt.args.authCallback.url = testServer.URL

			got, err := ac.doAuthCallback(tt.args.authCallback, tt.args.ai)
			if (err != nil) != tt.wantErr {
				t.Errorf("doAuthCallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("doAuthCallback() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_extractClientInfo(t *testing.T) {
	type args struct {
		urlStr string
	}
	tests := []struct {
		name    string
		args    args
		want    *clientInfo
		wantErr bool
	}{
		{
			name: "standard case",
			args: args{
				urlStr: "https://tenant.auth0.com/samlp/client_id",
			},
			want: &clientInfo{
				id:         "client_id",
				tenantName: "tenant",
			},
		},
		{
			name: "error case: invalid URL",
			args: args{
				urlStr: "https://example.com",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractClientInfo(tt.args.urlStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractClientInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractClientInfo() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseResponseForm(t *testing.T) {
	type args struct {
		responseForm string
	}
	tests := []struct {
		name    string
		args    args
		want    *authCallbackRequest
		wantErr bool
	}{
		{
			name: "standard case",
			args: args{
				responseForm: fmt.Sprintf(testSAMLFormHTMLFmt, "https://example.com/saml", "SAMLBase64Encoded"),
			},
			want: &authCallbackRequest{
				method: "POST",
				url: "https://example.com/saml",
				body: "RelayState=&SAMLResponse=SAMLBase64Encoded",
			},
		},
		{
			name: "error case: no method attribute on form element",
			args: args{
				responseForm: `<form name="hiddenform" action="https://example.com/saml"></form>`,
			},
			wantErr: true,
		},
		{
			name: "error case: no action attribute on form element",
			args: args{
				responseForm: `<form method="post" name="hiddenform"></form>`,
			},
			wantErr: true,
		},
		{
			name: "error case: input element in form element",
			args: args{
				responseForm: `<form method="post" name="hiddenform" action="https://example.com/saml"></form>`,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResponseForm(tt.args.responseForm)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponseForm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseResponseForm() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mustFindInputByName(t *testing.T) {
	type args struct {
		formHTML string
		name     string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "standard case",
			args: args{
				formHTML: fmt.Sprintf(testSAMLFormHTMLFmt, "https://example.com/saml", "SAMLBase64Encoded"),
				name: "SAMLResponse",
			},
			want: "SAMLBase64Encoded",
		},
		{
			name: "error case: SAML value is empty",
			args: args{
				formHTML: fmt.Sprintf(testSAMLFormHTMLFmt, "https://example.com/saml", ""),
				name: "SAMLResponse",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mustFindInputByName(tt.args.formHTML, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("mustFindInputByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mustFindInputByName() got = %v, want %v", got, tt.want)
			}
		})
	}
}
