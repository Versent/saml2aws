package okta

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

type stateTokenTests struct {
	title      string
	body       string
	stateToken string
	err        error
}

type parseMfaIdentifierTests struct {
	title      string
	identifier string
	authName   string
	index      int
}

func TestGetStateTokenFromOktaPageBody(t *testing.T) {
	tests := []stateTokenTests{
		{
			title:      "State token in body gets returned",
			body:       "someJavascriptCode();\nvar stateToken = '123456789';\nsomeOtherJavaScriptCode();",
			stateToken: "123456789",
			err:        nil,
		},
		{
			title:      "State token not in body causes error",
			body:       "someJavascriptCode();\nsomeOtherJavaScriptCode();",
			stateToken: "",
			err:        errors.New("cannot find state token"),
		},
		{
			title:      "State token with hyphen handled correctly",
			body:       "someJavascriptCode();\nvar stateToken = '12345\x2D6789';\nsomeOtherJavaScriptCode();",
			stateToken: "12345-6789",
			err:        nil,
		},
	}
	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			stateToken, err := getStateTokenFromOktaPageBody(test.body)
			assert.Equal(t, test.stateToken, stateToken)
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}

		})
	}
}

func TestExtractSessionToken(t *testing.T) {
	tests := []struct {
		name          string
		r             io.Reader
		expectedToken string
		expectedError string
	}{
		{
			name:          "response with session token",
			r:             strings.NewReader(`{"sessionToken": "xxxx"}`),
			expectedToken: "xxxx",
		},
		{
			name:          "response with no session token but with status",
			r:             strings.NewReader(`{"status": "invalid password"}`),
			expectedError: "response does not contain session token, received status is: \"invalid password\"",
		},
		{
			name:          "response with no session token and no status",
			r:             strings.NewReader(`{}`),
			expectedError: "response does not contain session token",
		},
		{
			name:          "response is not even json",
			r:             strings.NewReader(`const x = {}`),
			expectedError: "response does not contain session token",
		},
		{
			name:          "reader returns an error",
			r:             iotest.ErrReader(fmt.Errorf("failed to read")),
			expectedError: "error retrieving body from response: failed to read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := extractSessionToken(tc.r)
			if tc.expectedError != "" {
				if err == nil {
					t.Fatalf("Expected error, but got null")
				}
				if err.Error() != tc.expectedError {
					t.Fatalf("Expected error %q, but got %q",
						err.Error(), tc.expectedError,
					)
				}
			}
			if tc.expectedToken != "" {
				if err != nil {
					t.Fatalf("Expected token %q, but got error %v", tc.expectedToken, err)
				}
				if resp != tc.expectedToken {
					t.Fatalf("Expected token %q, but got %q", tc.expectedToken, resp)
				}
			}
		})
	}
}

func TestGetMfaChallengeContext(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	t.Run("Verify link without query parameters", func(t *testing.T) {
		oc, loginDetails := setupTestClient(t, ts, "PUSH")

		err := oc.setDeviceTokenCookie(loginDetails)
		assert.Nil(t, err)

		context, err := getMfaChallengeContext(oc, 0, fmt.Sprintf(`{
			"stateToken": "TOKEN",
			"_embedded": {
				"factors": [
					{
						"id": "PUSH",
						"provider": "OKTA",
						"factorType": "PUSH",
						"_links": {
							"verify": { "href": "%s/verify" }
						}
					}
				]
			}
		}`, ts.URL))
		assert.Nil(t, err)

		assert.Equal(t, ts.URL+"/verify?rememberDevice=true", context.oktaVerify)
	})

	t.Run("Verify link with query parameters", func(t *testing.T) {
		oc, loginDetails := setupTestClient(t, ts, "PUSH")

		err := oc.setDeviceTokenCookie(loginDetails)
		assert.Nil(t, err)

		context, err := getMfaChallengeContext(oc, 0, fmt.Sprintf(`{
			"stateToken": "TOKEN",
			"_embedded": {
				"factors": [
					{
						"id": "PUSH",
						"provider": "OKTA",
						"factorType": "PUSH",
						"_links": {
							"verify": { "href": "%s/verify?p=1" }
						}
					}
				]
			}
		}`, ts.URL))
		assert.Nil(t, err)

		assert.Equal(t, ts.URL+"/verify?p=1&rememberDevice=true", context.oktaVerify)
	})
}

func setupTestClient(t *testing.T, ts *httptest.Server, mfa string) (*Client, *creds.LoginDetails) {
	testTransport := http.DefaultTransport.(*http.Transport).Clone()
	testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	client, _ := provider.NewHTTPClient(testTransport, opts)
	ac := &Client{
		client:          client,
		targetURL:       ts.URL,
		mfa:             mfa,
		disableSessions: false,
		rememberDevice:  true,
	}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "user@example.com", Password: "test123"}
	return ac, loginDetails
}

func TestSetDeviceTokenCookie(t *testing.T) {
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = "https://idp.example.com/abcd"
	idpAccount.Username = "user@example.com"

	loginDetails := &creds.LoginDetails{
		Username: "user@example.com",
		Password: "abc123",
		URL:      "https://idp.example.com/abcd",
	}

	oc, err := New(idpAccount)
	assert.Nil(t, err)

	err = oc.setDeviceTokenCookie(loginDetails)
	assert.Nil(t, err)

	expectedDT := fmt.Sprintf("okta_%s_saml2aws", loginDetails.Username)
	actualDT := ""
	for _, c := range oc.client.Jar.Cookies(&url.URL{Scheme: "https", Host: "idp.example.com", Path: "/abc"}) {
		if c.Name == "DT" {
			actualDT = c.Value
		}
	}
	assert.NotEqual(t, actualDT, "")
	assert.Equal(t, expectedDT, actualDT)

}

func TestOktaCfgFlagsDefaultState(t *testing.T) {
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = "https://idp.example.com/abcd"
	idpAccount.Username = "user@example.com"

	oc, err := New(idpAccount)
	assert.Nil(t, err)

	assert.False(t, oc.disableSessions, fmt.Errorf("disableSessions should be false by default"))
	assert.True(t, oc.rememberDevice, fmt.Errorf("rememberDevice should be true by default"))
}

func TestOktaCfgFlagsCustomState(t *testing.T) {
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = "https://idp.example.com/abcd"
	idpAccount.Username = "user@example.com"

	idpAccount.DisableRememberDevice = true
	oc, err := New(idpAccount)
	assert.Nil(t, err)

	assert.False(t, oc.disableSessions, fmt.Errorf("disableSessions should be false by default"))
	assert.False(t, oc.rememberDevice, fmt.Errorf("DisableRememberDevice was set to true, so rememberDevice should be false"))

	idpAccount.DisableSessions = true

	oc, err = New(idpAccount)
	assert.Nil(t, err)

	assert.True(t, oc.disableSessions, fmt.Errorf("DisableSessions was set to true so disableSessions should be true"))
	assert.False(t, oc.rememberDevice, fmt.Errorf("DisablDisableSessionseRememberDevice was set to true, so rememberDevice should be false"))

}

func TestOktaParseMfaIdentifer(t *testing.T) {
	resp := `{
		"_embedded": {
			"factors": [
				{
					"factorType": "token:software:totp",
					"provider": "GOOGLE",
					"profile": {
						"credentialId": "dade.murphy@example.com"
					}
				},
				{
					"factorType":"webauthn",
					"provider":"FIDO",
					"profile":{
						"authenticatorName":"MacBook Touch ID"
					}
				},
				{
					"factorType":"webauthn",
					"provider":"FIDO",
					"profile":{
						"authenticatorName":"Yubikey 5"
					}
				}
			]
		}
	}`

	tests := []parseMfaIdentifierTests{
		{
			title:      "Google TOTP doesn't have a name",
			identifier: "GOOGLE TOKEN:SOFTWARE:TOTP",
			authName:   "",
			index:      0,
		},
		{
			title:      "WebAuthn tokens have names",
			identifier: "FIDO WEBAUTHN",
			authName:   "MacBook Touch ID",
			index:      1,
		},
		{
			title:      "A second webauthn token with a different name",
			identifier: "FIDO WEBAUTHN",
			authName:   "Yubikey 5",
			index:      2,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			identifier, authName := parseMfaIdentifer(resp, test.index)
			assert.Equal(t, test.identifier, identifier)
			assert.Equal(t, test.authName, authName)
		})
	}
}

func TestGetStateToken(t *testing.T) {

	persistedCookie := &http.Cookie{Name: "TestCookie", Value: "test"}
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Cookies(), persistedCookie)

		expected := "var stateToken = \"token1\";"
		_, err := w.Write([]byte(expected))
		assert.Nil(t, err)
	}))
	defer svr.Close()

	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	oc, err := New(idpAccount)
	assert.Nil(t, err)

	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(persistedCookie)

	stateToken, err := oc.getStateToken(req, loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, "token1", stateToken)
}

func TestVerifyMFA(t *testing.T) {

}
