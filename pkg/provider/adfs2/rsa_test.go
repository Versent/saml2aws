package adfs2

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func TestClient_getLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	c := Client{
		idpAccount: &cfg.IDPAccount{AmazonWebservicesURN: ""},
		client:     &http.Client{},
	}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}

	submitURL, authForm, err := c.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.True(t, strings.HasSuffix(submitURL, "/adfs/ls/idpinitiatedsignon"))
	require.Equal(t, url.Values{
		"UserName":   []string{"test"},
		"Password":   []string{"test123"},
		"AuthMethod": []string{"FormsAuthentication"},
		"Kmsi":       []string{"true"},
	}, authForm)
}

func TestClient_postLoginForm(t *testing.T) {

	data, err := ioutil.ReadFile("example/passcode.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	loginForm := url.Values{
		"UserName":   []string{"test"},
		"Password":   []string{"test123"},
		"AuthMethod": []string{"FormsAuthentication"},
	}

	c := Client{
		idpAccount: &cfg.IDPAccount{AmazonWebservicesURN: ""},
		client:     &http.Client{},
	}
	content, err := c.postLoginForm(ts.URL, loginForm)
	require.Nil(t, err)
	require.NotNil(t, content)
}

func TestClient_extractFormData(t *testing.T) {

	file, err := os.Open("example/passcode.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(file)
	require.Nil(t, err)
	form, actionURL, err := extractFormData(doc)
	require.Nil(t, err)
	require.Equal(t, "https://id.example.com:443/adfs/ls/idpinitiatedsignon", actionURL)
	require.Equal(t, "", form.Get("Passcode"))
	require.Equal(t, "Submit", form.Get("Submit"))
}
