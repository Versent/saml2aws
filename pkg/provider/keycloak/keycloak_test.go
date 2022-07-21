package keycloak

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"

	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

const (
	exampleLoginURL = "https://id.example.com/auth/realms/master/login-actions/authenticate?code=G5PSj-AJ7mC2wRS5yOA5NEGZ7BO97Y0_qUkS5zInmhQ&execution=e0c4f6fe-6f9a-435e-a7ff-d61eb2456d58&client_id=urn%3Aamazon%3Awebservices"
)

func TestClient_getLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, err := kc.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}, authForm)
}

func TestClient_getLoginFormRedirect(t *testing.T) {

	redirectData, err := ioutil.ReadFile("example/redirect.html")
	require.Nil(t, err)

	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count > 0 {
			_, _ = w.Write(data)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(bytes.Replace(redirectData, []byte(exampleLoginURL), []byte("http://"+r.Host), 1))
		}
		count++
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, err := kc.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}, authForm)
}

func TestClient_postLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	loginForm := url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	content, err := kc.postLoginForm(ts.URL, loginForm)
	require.Nil(t, err)
	require.NotNil(t, content)
}

func TestClient_postTotpForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	pr.Mock.On("RequestSecurityCode", "000000").Return("123456")

	authCtx := &authContext{"", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertCalled(t, "RequestSecurityCode", "000000")
}

func TestClient_postTotpFormWithProvidedMFAToken(t *testing.T) {

	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	authCtx := &authContext{"123456", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertNumberOfCalls(t, "RequestSecurityCode", 0)
}

func TestClient_postTotpFormWithMultipleAuthenticators(t *testing.T) {
	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	mfapage, err := ioutil.ReadFile("example/mfapage2authenticators.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(mfapage))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	authCtx := &authContext{"123456", 0, true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, uint(1), authCtx.authenticatorIndex)
	require.Equal(t, true, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	_, err = kc.postTotpForm(authCtx, ts.URL, doc)
	require.Nil(t, err)
	require.Equal(t, uint(2), authCtx.authenticatorIndex)
	require.Equal(t, false, authCtx.authenticatorIndexValid)
	require.Equal(t, "123456", authCtx.mfaToken)

	pr.Mock.AssertNumberOfCalls(t, "RequestSecurityCode", 0)
}

func TestClient_extractSamlResponse(t *testing.T) {
	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	samlResponse, err := extractSamlResponse(doc)
	require.Nil(t, err)
	require.Equal(t, samlResponse, "abc123")
}

func TestClient_containsTotpForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	require.True(t, containsTotpForm(doc))
}

func TestClient_extractWebauthnParameters(t *testing.T) {
	data, err := ioutil.ReadFile("example/webauthnPage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	credentialIDs, challenge, rpID, err := extractWebauthnParameters(doc)
	require.Nil(t, err)

	expectedCredentialIDs := []string{"pcFg5E6QIk0ZFfJxmf8cfUcb3hirl5Knl8aJ-mjC6MRjVu1dOiBBs51wtjS_O1eP2uiJfGiSL3D8R2cBLnoZyw", "pcFg5E6QIk0ZFfJxmf8efUcb3hirl5Knl8aJ-mjC6MRjVu1dOaBBs51wtjS_O1eP2uiJfGiSL3D8R2cBLnoZyw"}
	require.Equal(t, expectedCredentialIDs, credentialIDs)
	require.Equal(t, "J3NKWZPkSmqXuoKLtzzshg", challenge)
	require.Equal(t, "localhost", rpID)
}
