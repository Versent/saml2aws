package okta

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
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
		{
			title:      "javascript state token inside JSON",
			body:       `U0h8","stateToken":"c0ffeeda7e","helpLinks":{"help"`,
			stateToken: "c0ffeeda7e",
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

func TestVerifyMfa(t *testing.T) {
	verifyCounter := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify":
			switch verifyCounter {
			case 0, 1:
				_, err := w.Write([]byte(`{
					"stateToken": "TOKEN_2",
					"status": "MFA_CHALLENGE",
					"factorResult": "WAITING",
					"_embedded": {
						"factor": {
							"id": "PUSH",
							"provider": "OKTA",
							"factorType": "PUSH",
							"_embedded": {
								"challenge": {
									"correctAnswer": 92
								}
							}
						}
					}
				}`))
				assert.Nil(t, err)
			case 2:
				_, err := w.Write([]byte(`{
					"sessionToken": "TOKEN_3",
					"status": "SUCCESS"
				}`))
				assert.Nil(t, err)
			}
			verifyCounter++
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	t.Run("Push", func(t *testing.T) {
		oc, loginDetails := setupTestClient(t, ts, "PUSH")

		err := oc.setDeviceTokenCookie(loginDetails)
		assert.Nil(t, err)

		var out bytes.Buffer
		log.SetOutput(&out)
		context, err := verifyMfa(oc, "", &creds.LoginDetails{}, fmt.Sprintf(`{
			"stateToken": "TOKEN_1",
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
		log.SetOutput(os.Stderr)
		assert.Nil(t, err)
		assert.Contains(t, out.String(), "Correct Answer: 92")

		assert.Equal(t, context, "TOKEN_3")
	})
}

func TestVerifyMfa_Duo(t *testing.T) {
	t.Run("Duo Push", func(t *testing.T) {
		ts := setupTestDuoHttpServer(t, "Duo Push")
		defer ts.Close()
		oc, loginDetails := setupTestClient(t, ts, "DUO")

		err := oc.setDeviceTokenCookie(loginDetails)
		assert.Nil(t, err)

		var out bytes.Buffer
		log.SetOutput(&out)
		context, err := verifyMfa(oc, "host-from-argument", &creds.LoginDetails{DuoMFAOption: "Duo Push"}, fmt.Sprintf(`{
			"stateToken": "TOKEN_1",
			"status": "MFA_REQUIRED",
			"_embedded": {
				"factors": [
					{
						"id": "factor_id",
						"provider": "DUO",
						"factorType": "web",
						"_links": {
						  "verify": {
							"href": "%s/verify",
							"hints": {
							  "allow": [
								"POST"
							  ]
							}
						  }
					   }
					}
				]
			}
		}`, ts.URL))
		log.SetOutput(os.Stderr)
		assert.Nil(t, err)
		assert.Equal(t, "session-token-fffffff", context)
	})

	t.Run("Passcode", func(t *testing.T) {
		ts := setupTestDuoHttpServer(t, "Passcode")
    defer ts.Close()
		oc, loginDetails := setupTestClient(t, ts, "DUO")

		err := oc.setDeviceTokenCookie(loginDetails)
		assert.Nil(t, err)

		pr := &mocks.Prompter{}
		prompter.SetPrompter(pr)
		pr.Mock.On("StringRequired", "Enter passcode").Return("000000")

		var out bytes.Buffer
		log.SetOutput(&out)
		context, err := verifyMfa(oc, "host-from-argument", &creds.LoginDetails{DuoMFAOption: "Passcode"}, fmt.Sprintf(`{
			"stateToken": "TOKEN_1",
			"status": "MFA_REQUIRED",
			"_embedded": {
				"factors": [
					{
						"id": "factor_id",
						"provider": "DUO",
						"factorType": "web",
						"_links": {
						  "verify": {
							"href": "%s/verify",
							"hints": {
							  "allow": [
								"POST"
							  ]
							}
						  }
					   }
					}
				]
			}
		}`, ts.URL))
		log.SetOutput(os.Stderr)
		assert.Nil(t, err)
		assert.Equal(t, "session-token-fffffff", context)
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

func setupTestDuoHttpServer(t *testing.T, duoFactor string) (*httptest.Server) {
	verifyCounter := 0
	statusCounter := 0

  ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/frame/web/v1/auth":
			query, err := url.ParseQuery(r.URL.RawQuery)
			assert.Equal(t, url.Values{
				"parent": {"https://host-from-argument/signin/verify/duo/web"},
				"tx":     {"TX|blah_tx_blah"},
				"v":      {"2.8"}},
				query)
			assert.Nil(t, err)

			body, err := io.ReadAll(r.Body)
			defer r.Body.Close()
			assert.Nil(t, err)

			query, err = url.ParseQuery(string(body))
			assert.Equal(t, url.Values{
				"acting_ie_version":           {""},
				"color_depth":                 {"24"},
				"flash_version":               {""},
				"is_cef_browser":              {"false"},
				"is_ie_compatability_mode":    {""},
				"is_ipad_os":                  {"false"},
				"java_version":                {""},
				"parent":                      {"https://host-from-argument/signin/verify/duo/web"},
				"react_support":               {"true"},
				"react_support_error_message": {""},
				"screen_resolution_height":    {"1692"},
				"screen_resolution_width":     {"3008"},
				"tx":                          {"TX|blah_tx_blah"}},
				query)
			assert.Nil(t, err)

			_, err = w.Write([]byte(`<!DOCTYPE html>
			<html lang="en">
			  <body>
				<form>
				  <input type="hidden" name="sid" value="secret_sid">
				  <select name="device">
					<option value="phone1"></option>
				  </select>
				</form>
			  </body>
			</html>`))
			assert.Nil(t, err)
		case "/frame/prompt":
			query, err := url.ParseQuery(r.URL.RawQuery)
			assert.Equal(t, url.Values{}, query)
			assert.Nil(t, err)

			body, err := io.ReadAll(r.Body)
			defer r.Body.Close()
			assert.Nil(t, err)

			query, err = url.ParseQuery(string(body))

			switch duoFactor {
			case "Duo Push":
				assert.Equal(t, url.Values{
					"device":      {"phone1"},
					"factor":      {"Duo Push"},
					"out_of_date": {"false"},
					"sid":         {"secret_sid"},
			  }, query)
			case "Passcode":
				assert.Equal(t, url.Values{
					"device":      {"phone1"},
					"factor":      {"Passcode"},
					"passcode":		 {},
					"out_of_date": {"false"},
     			"sid":         {"secret_sid"},
				}, query)
			}

			assert.Nil(t, err)

			_, err = w.Write([]byte(`{"stat": "OK", "response": {"txid": "txid_1234"}}`))
			assert.Nil(t, err)
		case "/frame/status":
			switch statusCounter {
			case 0:
				query, err := url.ParseQuery(r.URL.RawQuery)
				assert.Equal(t, url.Values{}, query)
				assert.Nil(t, err)

				body, err := io.ReadAll(r.Body)
				defer r.Body.Close()
				assert.Nil(t, err)

				query, err = url.ParseQuery(string(body))
				assert.Equal(t, url.Values{
					"sid":  {"secret_sid"},
					"txid": {"txid_1234"},
				}, query)
				assert.Nil(t, err)

				_, err = w.Write([]byte(`{
				   "stat": "OK",
				   "response": {
					 "status": "Pushed a login request to your device...",
					 "status_code": "pushed"
				   }
				 }`))
				assert.Nil(t, err)
			case 1:
				query, err := url.ParseQuery(r.URL.RawQuery)
				assert.Equal(t, url.Values{}, query)
				assert.Nil(t, err)

				body, err := io.ReadAll(r.Body)
				defer r.Body.Close()
				assert.Nil(t, err)

				query, err = url.ParseQuery(string(body))
				assert.Equal(t, url.Values{
					"sid":  {"secret_sid"},
					"txid": {"txid_1234"},
				}, query)
				assert.Nil(t, err)
				_, err = w.Write([]byte(`{
					"stat": "OK",
					"response": {
					  "status": "Success. Logging you in...",
					  "status_code": "allow",
					  "result": "SUCCESS",
					  "result_url": "/frame/status/txid_1234"
					}
				  }`))
				assert.Nil(t, err)
			}
			statusCounter++
		case "/frame/status/txid_1234":
			query, err := url.ParseQuery(r.URL.RawQuery)
			assert.Equal(t, url.Values{}, query)
			assert.Nil(t, err)

			body, err := io.ReadAll(r.Body)
			defer r.Body.Close()
			assert.Nil(t, err)

			query, err = url.ParseQuery(string(body))
			assert.Equal(t, url.Values{
				"sid": {"secret_sid"},
			}, query)
			assert.Nil(t, err)

			_, err = w.Write([]byte(`{
				"stat": "OK",
				"response": {
				  "cookie": "AUTH|yumyum"
				}
			  }`))
			assert.Nil(t, err)
		case "/verify":
			switch verifyCounter {
			case 0:
				query, err := url.ParseQuery(r.URL.RawQuery)
				assert.Equal(t, url.Values{
					"rememberDevice": {"true"},
				}, query)
				assert.Nil(t, err)

				body, err := io.ReadAll(r.Body)
				defer r.Body.Close()
				assert.Nil(t, err)

				var requestBody interface{} = nil
				err = json.Unmarshal(body, &requestBody)
				assert.Equal(t, map[string]interface{}(map[string]interface{}{
					"rememberDevice": "true",
					"stateToken":     "TOKEN_1",
				}), requestBody)
				assert.Nil(t, err)

				_, err = fmt.Fprintf(w, `{
					"stateToken": "TOKEN_2",
					"status": "MFA_CHALLENGE",
					"factorResult": "WAITING",
					"_embedded": {
						"factor": {
							"id": "factor_id",
							"provider": "DUO",
							"factorType": "web",
							"_embedded": {
							  "verification": {
								"host": "%s",
								"signature": "TX|blah_tx_blah:APP|blah_app_blah",
								"_links": {
								  "complete": {
									"href": "https://%s/api/v1/authn/factors/factor_id/lifecycle/duoCallback"
								  }
								}
							  }
							}
						}
					}
				}`, r.Host, r.Host)
				assert.Nil(t, err)
			case 1:
				query, err := url.ParseQuery(r.URL.RawQuery)
				assert.Equal(t, url.Values{
					"rememberDevice": {"true"},
				}, query)
				assert.Nil(t, err)

				body, err := io.ReadAll(r.Body)
				defer r.Body.Close()
				assert.Nil(t, err)

				var requestBody interface{} = nil
				err = json.Unmarshal(body, &requestBody)
				assert.Equal(t, map[string]interface{}(map[string]interface{}{
					"rememberDevice": "true",
					"stateToken":     "TOKEN_1",
				}), requestBody)
				assert.Nil(t, err)

				_, err = w.Write([]byte(`{
				"sessionToken": "session-token-fffffff",
			}`))
				assert.Nil(t, err)
			}
			verifyCounter++
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))

	return ts
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
			identifier, authName, _ := parseMfaIdentifer(resp, test.index)
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

// anonymised from actual endpoint
const fakeEndpointForm = `
<form method="post" id="endpoint-health-form">
<input type="hidden" name="sid" value=HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ&#x3d;&#x7c;1683218343&#x7c;2a46eb852b3ef9f662304cee03d008daed6d71f6>
<input type="hidden" name="akey" value=UH7AkMtr7dqTzgeMefvQ>
<input type="hidden" name="txid" value=0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b>
<input type="hidden" name="response_timeout" value=15>
<input type="hidden" name="parent" value=https&#x3a;&#x2f;&#x2f;login.example.com&#x2f;signin&#x2f;verify&#x2f;duo&#x2f;web>
<input type="hidden" name="duo_app_url" value=https&#x3a;&#x2f;&#x2f;127.0.0.1&#x2f;report>
<input type="hidden" name="eh_service_url" value=https&#x3a;&#x2f;&#x2f;1.endpointhealth.duosecurity.com&#x2f;v1&#x2f;healthapp&#x2f;device&#x2f;health&#x3f;_req_trace_group&#x3d;fa4659be389f1c724121f27a_587a98dc11576a7ab8416a32>
<input type="hidden" name="eh_download_link" value=https&#x3a;&#x2f;&#x2f;dl.duosecurity.com&#x2f;DuoDeviceHealth-latest.pkg>

<input type="hidden" name="_xsrf" value="630ef22d00af14086a3a39d62374ea80" />
<input type="hidden" name="has_chromium_http_feature" value="true" />


</form>
`

type testServer struct {
	handlers []http.HandlerFunc
	t        *testing.T
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var h http.HandlerFunc
	if len(s.handlers) == 0 {
		s.t.Errorf("unexpected request: %v", r.URL.String())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h, s.handlers = s.handlers[0], s.handlers[1:]
	h(w, r)
}
func TestVerifyTrustedCert(t *testing.T) {
	host := ""

	handlers := []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/certifier-url", r.URL.Path)
			assert.Equal(t, fmt.Sprintf("https://%s/", host), r.Header.Get("Referer"))

			certURLRaw := r.URL.Query().Get("certUrl")
			assert.NotEmpty(t, certURLRaw)
			certURL, err := url.Parse(certURLRaw)
			assert.NoError(t, err)

			assert.Equal(t, "AJAX", certURL.Query().Get("type"))
			assert.Equal(t, "HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ=|1683218343|2a46eb852b3ef9f662304cee03d008daed6d71f6", certURL.Query().Get("sid"))

			assert.Equal(t, "0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b", certURL.Query().Get("certs_txid"))

			_, err = w.Write([]byte(`{"stat":"OK"}`))
			assert.NoError(t, err)
		},

		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/submit", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "1234567890", r.URL.Query().Get("tx"))
			assert.Equal(t, "2.8", r.URL.Query().Get("v"))

			assert.NoError(t, r.ParseForm())

			assert.Equal(t, "HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ=|1683218343|2a46eb852b3ef9f662304cee03d008daed6d71f6", r.Form.Get("sid"))
			assert.Equal(t, "0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b", r.Form.Get("certs_txid"))
			assert.Equal(t, fmt.Sprintf("https://%s/certs-url", host), r.Form.Get("certs_url"))
			assert.Equal(t, fmt.Sprintf("https://%s/certifier-url", host), r.Form.Get("certifier_url"))

		},
	}

	mockServer := &testServer{handlers: handlers, t: t}

	ts := httptest.NewTLSServer(mockServer)
	defer ts.Close()

	oc, _ := setupTestClient(t, ts, "PUSH")
	upstreamURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("couldn't parse URL: %v", err)
	}

	host = upstreamURL.Host
	submitURL := ts.URL + "/submit"

	q := url.Values{}
	q.Add("tx", "1234567890")
	q.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", host))
	q.Add("v", "2.8")

	fakeForm := fmt.Sprintf(`
<form method="post" id="client_cert_form">
<input type="hidden" name="sid" value=HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ&#x3d;&#x7c;1683218343&#x7c;2a46eb852b3ef9f662304cee03d008daed6d71f6>
<input type="hidden" name="certs_txid" value=0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b>
<input type="hidden" name="certs_url" value=https&#x3a;&#x2f;&#x2f;%s&#x2f;certs-url>
<input type="hidden" name="certifier_url" value=https&#x3a;&#x2f;&#x2f;%s&#x2f;certifier-url>

<input type="hidden" name="_xsrf" value="630ef22d00af14086a3a39d62374ea80" />
</form>
`, host, host)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(fakeForm))
	if err != nil {
		t.Fatalf("failed to validate document: %v, ", err)
	}

	_, err = verifyTrustedCert(oc, doc, host, submitURL, q)
	assert.NoError(t, err)
	assert.Empty(t, mockServer.handlers)
}

func TestVerifyEndpointHealth(t *testing.T) {
	duoTX := "1234567890"
	host := ""

	handlers := []http.HandlerFunc{
		// alive
		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/alive", r.URL.Path)
			assert.Equal(t, fmt.Sprintf("https://%s/", host), r.Header.Get("Referer"))
			assert.Equal(t, fmt.Sprintf("https://%s", host), r.Header.Get("Origin"))
			assert.NotEmpty(t, r.URL.Query().Get("_"))
		},
		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/report", r.URL.Path)
			assert.Equal(t, fmt.Sprintf("https://%s/", host), r.Header.Get("Referer"))
			assert.Equal(t, fmt.Sprintf("https://%s", host), r.Header.Get("Origin"))
			assert.Equal(t, "0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b", r.URL.Query().Get("txid"))
			assert.NotEmpty(t, r.URL.Query().Get("eh_service_url"))
		},
		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/frame/check_endpoint_app_status", r.URL.Path)
			assert.Equal(t, host, r.Header.Get("Referer"))
			assert.Equal(t, "0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b", r.URL.Query().Get("txid"))
			assert.Equal(t, "HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ=|1683218343|2a46eb852b3ef9f662304cee03d008daed6d71f6", r.URL.Query().Get("sid"))
			assert.Equal(t, "XMLHttpRequest", r.Header.Get("X-Requested-With"))

		},

		func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/submit", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, duoTX, r.URL.Query().Get("tx"))
			assert.Equal(t, "2.8", r.URL.Query().Get("v"))

			assert.NoError(t, r.ParseForm())

			assert.Equal(t, "HAlorymR7ZuV2CxZz9T10jABE4jzkWFBJYLEnlF4nUwCqQ=|1683218343|2a46eb852b3ef9f662304cee03d008daed6d71f6", r.Form.Get("sid"))
			assert.Equal(t, "0dcfcbe4-5e20-47a3-9037-cb1d1bf4ad5b", r.Form.Get("txid"))
			assert.Equal(t, "https://1.endpointhealth.duosecurity.com/v1/healthapp/device/health?_req_trace_group=fa4659be389f1c724121f27a_587a98dc11576a7ab8416a32", r.Form.Get("eh_service_url"))
			assert.Equal(t, "UH7AkMtr7dqTzgeMefvQ", r.Form.Get("akey"))
			assert.Equal(t, "15", r.Form.Get("response_timeout"))
			assert.Equal(t, "https://login.example.com/signin/verify/duo/web", r.Form.Get("parent"))
			assert.Equal(t, "https://127.0.0.1/report", r.Form.Get("duo_app_url"))
			assert.Equal(t, "https://dl.duosecurity.com/DuoDeviceHealth-latest.pkg", r.Form.Get("eh_download_link"))
		},
	}

	ts := httptest.NewTLSServer(
		&testServer{handlers: handlers, t: t})
	defer ts.Close()

	oc, _ := setupTestClient(t, ts, "PUSH")
	upstreamURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("couldn't parse URL: %v", err)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(fakeEndpointForm))
	if err != nil {
		t.Fatalf("failed to validate document: %v, ", err)
	}

	host = upstreamURL.Host
	submitURL := ts.URL + "/submit"

	q := url.Values{}
	q.Add("tx", "1234567890")
	q.Add("parent", fmt.Sprintf("https://%s/signin/verify/duo/web", host))
	q.Add("v", "2.8")

	_, err = verifyEndpointHealth(oc, doc, host, host, host, submitURL, q)
	if err != nil {
		t.Fatalf("failed to verify endpoint health: %v", err)
	}
}
