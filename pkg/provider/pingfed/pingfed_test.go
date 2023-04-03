package pingfed

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

func TestMakeAbsoluteURL(t *testing.T) {
	require.Equal(t, makeAbsoluteURL("/a", "https://example.com"), "https://example.com/a")
	require.Equal(t, makeAbsoluteURL("https://foo.com/a/b", "https://bar.com"), "https://foo.com/a/b")
}

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsLogin, "example/login.html", true},
	{docIsLogin, "example/login2.html", true},
	{docIsLogin, "example/otp.html", false},
	{docIsLogin, "example/swipe.html", false},
	{docIsLogin, "example/form-redirect.html", false},
	{docIsLogin, "example/webauthn.html", false},
	{docIsOTP, "example/login.html", false},
	{docIsOTP, "example/otp.html", true},
	{docIsOTP, "example/swipe.html", false},
	{docIsOTP, "example/form-redirect.html", false},
	{docIsOTP, "example/webauthn.html", false},
	{docIsSwipe, "example/login.html", false},
	{docIsSwipe, "example/otp.html", false},
	{docIsSwipe, "example/swipe.html", true},
	{docIsSwipe, "example/form-redirect.html", false},
	{docIsSwipe, "example/webauthn.html", false},
	{docIsFormRedirect, "example/login.html", false},
	{docIsFormRedirect, "example/otp.html", false},
	{docIsFormRedirect, "example/swipe.html", false},
	{docIsFormRedirect, "example/form-redirect.html", true},
	{docIsFormRedirect, "example/webauthn.html", false},
	{docIsWebAuthn, "example/login.html", false},
	{docIsWebAuthn, "example/otp.html", false},
	{docIsWebAuthn, "example/swipe.html", false},
	{docIsWebAuthn, "example/form-redirect.html", false},
	{docIsWebAuthn, "example/webauthn.html", true},
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

func TestHandleLogin(t *testing.T) {
	ac := Client{}
	loginDetails := creds.LoginDetails{
		Username: "fdsa",
		Password: "secret",
		URL:      "https://example.com/foo",
	}
	ctx := context.WithValue(context.Background(), ctxKey("login"), &loginDetails)

	data, err := os.ReadFile("example/login.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	_, req, err := ac.handleLogin(ctx, doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "pf.username=fdsa")
	require.Contains(t, s, "pf.pass=secret")
}

func TestHandleOTP(t *testing.T) {
	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "Enter passcode").Return("5309")

	data, err := os.ReadFile("example/otp.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	pingfedURL := &url.URL{
		Scheme: "https",
		Host:   "authenticator.pingone.com",
		Path:   "/pingid/ppm/auth/otp",
	}
	jar, err := cookiejar.New(&cookiejar.Options{})
	require.Nil(t, err)
	jar.SetCookies(pingfedURL, []*http.Cookie{{
		Name:    ".csrf",
		Secure:  true,
		Expires: time.Now().Add(time.Hour * 24 * 30),
		Value:   "some-token",
	}})

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{Jar: jar}, Options: opts}}
	_, req, err := ac.handleOTP(context.Background(), doc, pingfedURL)
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "otp=5309")
	require.Contains(t, s, "csrfToken=some-token")
}

func TestHandleFormRedirect(t *testing.T) {
	data, err := os.ReadFile("example/form-redirect.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleFormRedirect(context.Background(), doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "ppm_request=secret")
	require.Contains(t, s, "idp_account_id=some-uuid")
}

func TestHandleWebAuthn(t *testing.T) {
	data, err := os.ReadFile("example/webauthn.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	ac := Client{}
	_, req, err := ac.handleWebAuthn(context.Background(), doc, &url.URL{})
	require.Nil(t, err)

	b, err := io.ReadAll(req.Body)
	require.Nil(t, err)

	s := string(b[:])
	require.Contains(t, s, "isWebAuthnSupportedByBrowser=false")
}
