package provider

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/cookiejar"
	"github.com/GESkunkworks/gossamer3/pkg/dump"
	"github.com/avast/retry-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

// HTTPClient gossamer3 http client which extends the existing client
type HTTPClient struct {
	http.Client
	CheckResponseStatus func(*http.Request, *http.Response) error
	Options             *HTTPClientOptions
}

const (
	DefaultAttemptsCount = 1
	DefaultRetryDelay    = time.Duration(1) * time.Second
)

type HTTPClientOptions struct {
	IsWithRetries bool //http retry feature switch
	AttemptsCount uint
	RetryDelay    time.Duration
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

func BuildHttpClientOpts(account *cfg.IDPAccount) *HTTPClientOptions {
	opts := &HTTPClientOptions{}
	atmt, atmtErr := strconv.ParseUint(account.HttpAttemptsCount, 10, 0)
	if opts.IsWithRetries = atmtErr == nil; opts.IsWithRetries {
		opts.AttemptsCount = uint(atmt)
	} else {
		opts.AttemptsCount = DefaultAttemptsCount
	}

	delay, delayErr := strconv.ParseUint(account.HttpRetryDelay, 10, 0)
	if delayErr != nil {
		opts.RetryDelay = DefaultRetryDelay
	} else {
		opts.RetryDelay = time.Duration(delay) * time.Second
	}

	return opts
}

// NewHTTPClient configure the default http client used by the providers
func NewHTTPClient(tr http.RoundTripper, opts *HTTPClientOptions) (*HTTPClient, error) {

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := http.Client{Transport: tr, Jar: jar}

	return &HTTPClient{client, nil, opts}, nil
}

// Do do the request
func (hc *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", cfg.GetUserAgent())

	var resp *http.Response
	var err error

	if hc.Options.IsWithRetries {
		resp, err = hc.doWithRetry(req)
	} else {
		hc.logHTTPRequest(req)
		resp, err = hc.Client.Do(req)
	}
	if err != nil {
		return resp, err
	}

	// if a response check has been configured
	if hc.CheckResponseStatus != nil {
		err = hc.CheckResponseStatus(req, resp)
		if err != nil {
			return resp, err
		}
	}

	hc.logHTTPResponse(resp)

	return resp, err
}

func (hc *HTTPClient) doWithRetry(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := retry.Do(
		func() error {
			hc.logHTTPRequest(req)
			clientResp, err := hc.Client.Do(req)
			if err != nil {
				return err
			}
			resp = clientResp
			return nil
		},
		retry.Attempts(hc.Options.AttemptsCount),
		retry.Delay(hc.Options.RetryDelay),
		retry.OnRetry(
			func(n uint, err error) {
				logrus.
					WithField("Attempt #", n).
					WithField("Caused by", fmt.Errorf("%v", err)).
					Debug("Retry")
			}),
	)
	return resp, err

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

// SuccessOrRedirectResponseValidator this validates the response code is within range of 200 - 399
func SuccessOrRedirectResponseValidator(req *http.Request, resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}

	return errors.Errorf("request for url: %s failed status: %s", req.URL.String(), resp.Status)
}

func (hc *HTTPClient) logHTTPRequest(req *http.Request) {

	if dump.ContentEnable() {
		log.Println(dump.RequestString(req))
		return
	}

	logrus.WithField("http", "client").WithFields(logrus.Fields{
		"URL":    req.URL.String(),
		"method": req.Method,
	}).Debug("HTTP Req")
}

func (hc *HTTPClient) logHTTPResponse(resp *http.Response) {

	if dump.ContentEnable() {
		log.Println(dump.ResponseString(resp))
		return
	}

	logrus.WithField("http", "client").WithFields(logrus.Fields{
		"Status": resp.Status,
	}).Debug("HTTP Res")
}
