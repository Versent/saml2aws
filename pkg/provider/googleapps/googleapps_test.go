package googleapps

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

func TestExtractInputByName(t *testing.T) {
	html := `<html><body><input name="logincaptcha" value="test error message"\></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	captcha := mustFindInputByName(doc, "logincaptcha")
	require.Equal(t, "test error message", captcha)
}

func TestExtractInputsByFormQuery(t *testing.T) {
	html := `<html><body><form id="dev" action="http://example.com/test"><input name="pass" value="test error message"\></form></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	doc.Url = &url.URL{
		Scheme: "https",
		Host:   "google.com",
		Path:   "foobar",
	}

	form, actionURL, err := extractInputsByFormQuery(doc, "#dev")
	require.Nil(t, err)
	require.Equal(t, "http://example.com/test", actionURL)
	require.Equal(t, "test error message", form.Get("pass"))

	form2, actionURL2, err := extractInputsByFormQuery(doc, `[action$="/test"]`)
	require.Nil(t, err)
	require.Equal(t, "http://example.com/test", actionURL2)
	require.Equal(t, "test error message", form2.Get("pass"))
}
func TestExtractErrorMsg(t *testing.T) {
	html := `<html><body><span class="error-msg">test error message</span></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	captcha := mustFindErrorMsg(doc)
	require.Equal(t, "test error message", captcha)
}

func TestContentContainsMessage(t *testing.T) {
	html := `<html><body><h2>This extra step shows it’s really you trying to sign in</h2></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	txt := extractNodeText(doc, "h2", "This extra step shows it’s really you trying to sign in")
	require.Equal(t, "This extra step shows it’s really you trying to sign in", txt)
}

func TestContentContainsMessage2(t *testing.T) {
	html := `<html><body><h2>This extra step shows that it’s really you trying to sign in</h2></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)

	txt := extractNodeText(doc, "h2", "This extra step shows that it’s really you trying to sign in")
	require.Equal(t, "This extra step shows that it’s really you trying to sign in", txt)
}

func TestChallengePage(t *testing.T) {

	data, err := ioutil.ReadFile("example/challenge-totp.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test", Password: "test123"}
	authForm := url.Values{}

	challengeDoc, err := kc.loadChallengePage(ts.URL, "https://accounts.google.com/signin/challenge/sl/password", authForm, loginDetails)
	require.Nil(t, err)
	require.NotNil(t, challengeDoc)
}

func TestExtractDataAttributes(t *testing.T) {
	data, err := ioutil.ReadFile("example/challenge-prompt.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	dataAttrs := extractDataAttributes(doc, "div[data-context]", []string{"data-context", "data-gapi-url", "data-tx-id", "data-tx-lifetime"})

	require.Equal(t, "https://apis.google.com/js/base.js", dataAttrs["data-gapi-url"])
}
