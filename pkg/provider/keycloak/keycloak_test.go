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

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	pr.Mock.On("RequestSecurityCode", "000000").Return("123456")

	mfaToken := ""
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(ts.URL, mfaToken, doc)
	require.Nil(t, err)

	pr.Mock.AssertCalled(t, "RequestSecurityCode", "000000")
}

func TestClient_postTotpFormWithProvidedMFAToken(t *testing.T) {

	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)

	mfaToken := "123456"
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	_, err = kc.postTotpForm(ts.URL, mfaToken, doc)
	require.Nil(t, err)
	pr.Mock.AssertNumberOfCalls(t, "RequestSecurityCode", 0)
}

func TestClient_extractSamlResponse(t *testing.T) {
	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	require.Equal(t, extractSamlResponse(doc), "abc123")
}

func TestClient_containsTotpForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	require.True(t, containsTotpForm(doc))
}
