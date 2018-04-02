package provider

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"time"

	"github.com/briandowns/spinner"
	"golang.org/x/net/publicsuffix"
)

// HTTPClient saml2aws http client which extends the existing client
type HTTPClient struct {
	http.Client
}

// NewDefaultTransport configure a transport with the TLS skip verify option
func NewDefaultTransport(skipVerify bool) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skipVerify},
	}
}

// NewHTTPClient configure the default http client used by the providers
func NewHTTPClient(tr http.RoundTripper) (*HTTPClient, error) {

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := http.Client{Transport: tr, Jar: jar}

	return &HTTPClient{client}, nil
}

// Do do the request
func (hc *HTTPClient) Do(req *http.Request) (*http.Response, error) {

	cs := spinner.CharSets[14]

	// use a NON unicode spinner for windows
	if runtime.GOOS == "windows" {
		cs = spinner.CharSets[26]
	}

	s := spinner.New(cs, 100*time.Millisecond)
	defer func() {
		s.Stop()
	}()
	s.Start()
	return hc.Client.Do(req)
}

// DisableFollowRedirect disable redirects
func (hc *HTTPClient) DisableFollowRedirect() {
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

// EnableFollowRedirect enable redirects
func (hc *HTTPClient) EnableFollowRedirect() {
	hc.CheckRedirect = nil
}
