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
	"github.com/versent/saml2aws/mocks"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider"
)

const (
	exampleLoginURL = "https://id.example.com/auth/realms/master/login-actions/authenticate?code=G5PSj-AJ7mC2wRS5yOA5NEGZ7BO97Y0_qUkS5zInmhQ&execution=e0c4f6fe-6f9a-435e-a7ff-d61eb2456d58&client_id=urn%3Aamazon%3Awebservices"
)

func TestClient_getLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer ts.Close()

	kc := Client{client: &provider.HTTPClient{Client: http.Client{}}}
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

func TestClient_postLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer ts.Close()

	loginForm := url.Values{
		"username": []string{"test"},
		"password": []string{"test123"},
		"login":    []string{"Log in"},
	}

	kc := Client{client: &provider.HTTPClient{Client: http.Client{}}}

	content, err := kc.postLoginForm(ts.URL, loginForm)
	require.Nil(t, err)
	require.NotNil(t, content)
}

func TestClient_postTotpForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/assertion.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer ts.Close()

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	pr := &mocks.Prompter{}

	pr.Mock.On("RequestSecurityCode", "000000").Return("111222")

	kc := Client{client: &provider.HTTPClient{Client: http.Client{}}, prompter: pr}

	kc.postTotpForm(ts.URL, doc)
}

func TestClient_containsTotpForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	require.True(t, containsTotpForm(doc))
}
