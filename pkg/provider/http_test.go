package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientDoGetOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	rt := NewDefaultTransport(false)
	opts := &HTTPClientOptions{IsWithRetries: false}
	hc, err := NewHTTPClient(rt, opts)
	require.Nil(t, err)

	// hc := &HTTPClient{Client: http.Client{}}

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Nil(t, err)

	require.Equal(t, 200, res.StatusCode)
}

func TestClientDisableRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(302)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	rt := NewDefaultTransport(false)

	opts := &HTTPClientOptions{IsWithRetries: false}
	hc, err := NewHTTPClient(rt, opts)
	require.Nil(t, err)

	hc.DisableFollowRedirect()

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestClientDoResponseCheck(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	opts := &HTTPClientOptions{IsWithRetries: false}
	hc := &HTTPClient{Client: http.Client{}, Options: opts}

	hc.CheckResponseStatus = SuccessOrRedirectResponseValidator

	req, err := http.NewRequest("GET", ts.URL, nil)
	require.Nil(t, err)

	res, err := hc.Do(req)
	require.Error(t, err)
	require.Equal(t, 400, res.StatusCode)
}
