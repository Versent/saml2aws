package mock

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// New returns an instance of the mock OneLogin indetity provider.
func New(t *testing.T, requests []ExpectedRequest) *httptest.Server {
	h := mockHandler(t, requests)
	return httptest.NewServer(h)
}

// ExpectedRequest represents a request that the mock identity provider expects and its predefined response.
type ExpectedRequest struct {
	reqBody    []byte
	reqHeaders http.Header
	reqMethod  string
	reqPath    string

	resBody    []byte
	resHeaders http.Header
	resStatus  int
}

func mockHandler(t *testing.T, requests []ExpectedRequest) http.Handler {
	// WIP
	return http.NotFoundHandler()
}
