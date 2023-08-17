package jumpcloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

type test struct {
	code     int
	err      string
	testCase string
}

func Test_jumpCloudProtectAuth(t *testing.T) {
	jumpCloudPushResp := JumpCloudPushResponse{
		ExpiresAt: time.Now().Add(1 * time.Minute).UTC(),
		ID:        "foo",
	}

	pendingCnt := 1
	maxPending := 2
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// using token here as a clue to mock responses
		switch token := r.Header.Get("X-Xsrftoken"); {
		case token == "happy":
			switch r.URL.Path {
			case "/":
				returnResp(t, "pending", 200, &jumpCloudPushResp, w)
			case fmt.Sprintf("/%s", jumpCloudPushResp.ID):
				returnResp(t, "accepted", 200, &jumpCloudPushResp, w)
			case fmt.Sprintf("/%s/login", jumpCloudPushResp.ID):
				_, err := w.Write([]byte(`{}`))
				require.Nil(t, err)
			}

		case token == "loop twice until accepted":
			switch r.URL.Path {
			case "/":
				returnResp(t, "pending", 200, &jumpCloudPushResp, w)
			case fmt.Sprintf("/%s", jumpCloudPushResp.ID):
				pendingCnt += 1
				if pendingCnt == maxPending {
					returnResp(t, "accepted", 200, &jumpCloudPushResp, w)
				} else {
					returnResp(t, "pending", 200, &jumpCloudPushResp, w)
				}
			case fmt.Sprintf("/%s/login", jumpCloudPushResp.ID):
				_, err := w.Write([]byte(`{}`))
				require.Nil(t, err)
			}

		case token == "payload error":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{}`))
			require.Nil(t, err)

		case token == "received expired":
			switch r.URL.Path {
			case "/":
				jumpCloudPushResp.Status = "pending"
				bytes, err := json.Marshal(&jumpCloudPushResp)
				require.Nil(t, err)
				_, _ = w.Write(bytes)
			case fmt.Sprintf("/%s", jumpCloudPushResp.ID):
				returnResp(t, "expired", http.StatusOK, &jumpCloudPushResp, w)
			}

		case token == "received denied":
			switch r.URL.Path {
			case "/":
				jumpCloudPushResp.Status = "pending"
				bytes, err := json.Marshal(&jumpCloudPushResp)
				require.Nil(t, err)
				_, _ = w.Write(bytes)
			case fmt.Sprintf("/%s", jumpCloudPushResp.ID):
				returnResp(t, "denied", http.StatusUnauthorized, &jumpCloudPushResp, w)
			}

		case token == "login error":
			switch r.URL.Path {
			case "/":
				jumpCloudPushResp.Status = "pending"
				bytes, err := json.Marshal(&jumpCloudPushResp)
				require.Nil(t, err)
				_, _ = w.Write(bytes)
			case fmt.Sprintf("/%s", jumpCloudPushResp.ID):
				jumpCloudPushResp.Status = "accepted"
				bytes, err := json.Marshal(&jumpCloudPushResp)
				require.Nil(t, err)
				_, _ = w.Write(bytes)
			case fmt.Sprintf("/%s/login", jumpCloudPushResp.ID):
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}))
	defer ts.Close()

	client, err := New(&cfg.IDPAccount{Provider: "JumpCloud", MFA: "PUSH"})
	require.Nil(t, err)

	tests := []test{
		{testCase: "happy", code: http.StatusOK},
		{testCase: "loop twice until accepted", code: http.StatusOK},
		{testCase: "login error", code: http.StatusInternalServerError},
		{testCase: "payload error", code: http.StatusInternalServerError, err: "error retrieving JumpCloud PUSH payload, non 200 status returned"},
		{testCase: "received expired", err: "didn't receive accepted, status=expired"},
		{testCase: "received denied", err: "received non 200 http code, http code = 401"},
	}

	for _, test := range tests {
		t.Run(test.testCase, func(t *testing.T) {
			resp, err := client.jumpCloudProtectAuth(ts.URL, test.testCase)
			if test.err == "" {
				require.Nil(t, err)
				require.Equal(t, test.code, resp.StatusCode)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}

	require.Equal(t, pendingCnt, maxPending)
}

func returnResp(t *testing.T, status string, statusCode int, j *JumpCloudPushResponse, w http.ResponseWriter) {
	j.Status = status
	bytes, err := json.Marshal(j)
	require.Nil(t, err)
	w.WriteHeader(statusCode)
	_, err = w.Write(bytes)
	require.Nil(t, err)
}
