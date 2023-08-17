package googleapps

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

func TestPasswordFormChallengeId1(t *testing.T) {
	data, err := os.ReadFile("example/form-password-challengeid-1.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test-id1@example.com", Password: "test123"}

	authForm := url.Values{}
	authForm.Set("bgresponse", "js_enabled")
	authForm.Set("Email", loginDetails.Username)

	passwordURL, passwordForm, err := kc.loadLoginPage(ts.URL, loginDetails.URL+"&hl=en&loc=US", authForm)
	require.Nil(t, err)
	require.NotEmpty(t, passwordURL)
	require.Equal(t, "1", passwordForm.Get("challengeId"))
	// check pre-filled email
	require.NotEmpty(t, passwordForm.Get("Email"))
	// check password form
	require.Empty(t, passwordForm.Get("Passwd"))
}

func TestPasswordFormChallengeId2(t *testing.T) {
	data, err := os.ReadFile("example/form-password-challengeid-2.html")
	require.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	kc := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "test-id2@example.com", Password: "test123"}

	authForm := url.Values{}
	authForm.Set("bgresponse", "js_enabled")
	authForm.Set("Email", loginDetails.Username)

	passwordURL, passwordForm, err := kc.loadLoginPage(ts.URL, loginDetails.URL+"&hl=en&loc=US", authForm)
	require.Nil(t, err)
	require.NotEmpty(t, passwordURL)
	require.Equal(t, "2", passwordForm.Get("challengeId"))
	// check pre-filled email
	require.NotEmpty(t, passwordForm.Get("Email"))
	// check password form
	require.Empty(t, passwordForm.Get("Passwd"))
}

func TestChallengePage(t *testing.T) {

	data, err := os.ReadFile("example/challenge-totp.html")
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
	data, err := os.ReadFile("example/challenge-prompt.html")
	require.Nil(t, err)
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	dataAttrs := extractDataAttributes(doc, "div[data-context]", []string{"data-context", "data-gapi-url", "data-tx-id", "data-tx-lifetime"})

	require.Equal(t, "https://apis.google.com/js/base.js", dataAttrs["data-gapi-url"])
}

func TestWrongPassword(t *testing.T) {
	passwordErrorId := "passwordError"
	html := `<html><body><span class="Qx8Abe" id="` + passwordErrorId + `">Wrong password. Try again or click Forgot password to reset it.</span></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)
	txt := doc.Selection.Find("#" + passwordErrorId).Text()
	require.NotEqual(t, "", txt)
}

func TestMustEnable2StepVerification(t *testing.T) {
	html := `<html><body><section class="aN1Vld "><div class="yOnVIb" jsname="MZArnb"><div jsname="x2WF9"><p class="vOZun">Your sign-in settings donâ€™t meet your organizationâ€™s 2-Step Verification policy.</p><p class="vOZun">Contact your admin for more info.</p></div><input type="hidden" name="identifierInput" value="" id="identifierId"></div></section></body></html>`

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.Nil(t, err)
	twoStepIsMissingErr := isMissing2StepSetup(doc)
	require.Error(t, twoStepIsMissingErr)
	require.Equal(t, twoStepIsMissingErr.Error(), "Because of your organization settings, you must set-up 2-Step Verification in your account")
}

func TestExtractDevicePushExtraNumber(t *testing.T) {
	data1, err := os.ReadFile("example/challenge-extra-number.html")
	require.Nil(t, err)
	doc1, err := goquery.NewDocumentFromReader(bytes.NewReader(data1))
	require.Nil(t, err)
	require.Equal(t, "89", extractDevicePushExtraNumber(doc1))

	for _, filename := range []string{"example/challenge-prompt.html", "example/challenge-totp.html"} {
		data2, err := os.ReadFile(filename)
		require.Nil(t, err)
		doc2, err := goquery.NewDocumentFromReader(bytes.NewReader(data2))
		require.Nil(t, err)
		require.Equal(t, "", extractDevicePushExtraNumber(doc2))
	}
}
