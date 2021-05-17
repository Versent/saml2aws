package f5apm

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/versent/saml2aws/v2/pkg/creds"

	"github.com/versent/saml2aws/v2/pkg/provider"

	"github.com/stretchr/testify/require"
)

func TestClient_getLoginForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	t.Log(ac)
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "groundcontrol", Password: "majortom"}
	t.Log(loginDetails)

	authForm, err := ac.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, url.Values{
		"username": []string{"groundcontrol"},
		"password": []string{"majortom"},
		"vhost":    []string{"standard"},
	}, authForm)
}
func TestClient_postLoginForm_user_pass(t *testing.T) {
	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	require.Nil(t, err)
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	t.Log(ac)
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "groundcontrol", Password: "majortom"}
	t.Log(loginDetails)

	authForm := url.Values{}
	authForm.Add("username", "groundcontrol")
	authForm.Add("password", "majortom")
	resData, err := ac.postLoginForm(loginDetails, authForm)
	require.Nil(t, err)
	require.Equal(t, data, resData)
}

func TestClient_containsMFAForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/mfapage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	mfaFound, mfaMethods := containsMFAForm(doc)
	require.True(t, mfaFound)
	require.Equal(t, []string{"push", "token"}, mfaMethods)
}

func TestClient_containsMFAForm_False(t *testing.T) {
	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	mfaFound, mfaMethods := containsMFAForm(doc)
	require.False(t, mfaFound)
	require.Equal(t, []string(nil), mfaMethods)
}
