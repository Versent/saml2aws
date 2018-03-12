package provider

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"

	"golang.org/x/net/publicsuffix"
)

// HTTPClient saml2aws http client which extends the existing client
type HTTPClient struct {
	http.Client
}

// NewDefaultTransport configure a transport with the TLS skip verify option
func NewDefaultTransport(skipVerify bool) http.RoundTripper {
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

// DisableFollowRedirect disable redirects
func (client *HTTPClient) DisableFollowRedirect() {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
}

// EnableFollowRedirect enable redirects
func (client *HTTPClient) EnableFollowRedirect() {
	client.CheckRedirect = nil
}
