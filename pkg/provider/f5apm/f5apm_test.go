package f5apm

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/versent/saml2aws/pkg/creds"

	"github.com/versent/saml2aws/pkg/provider"

	"github.com/stretchr/testify/require"
)

const (
	exampleLoginURL = ""
)

func TestClient_getLoginForm(t *testing.T) {
	data, err := ioutil.ReadFile("example/loginpage.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer ts.Close()

	ac := Client{client: &provider.HTTPClient{Client: http.Client{}}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "groundcontrol", Password: "majortom"}

	submitURL, authForm, err := ac.getLoginForm(loginDetails)
	require.Nil(t, err)
	require.Equal(t, exampleLoginURL, submitURL)
	require.Equal(t, url.Values{
		"username": []string{"groundcontrol"},
		"password": []string{"majortom"},
		"vhost":    []string{"standard"},
	}, authForm)
}
