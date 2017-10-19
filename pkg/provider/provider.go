package provider

import (
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

// HTTPClient saml2aws http client which extends the existing client
type HTTPClient struct {
	http.Client
}

// NewHTTPClient configure the default http client used by the providers
func NewHTTPClient(tr *http.Transport) (*HTTPClient, error) {

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
