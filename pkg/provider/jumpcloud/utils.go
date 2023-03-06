package jumpcloud

import (
	"bytes"
	"io"
	"net/http"
)

func ensureHeaders(xsrfToken string, req *http.Request) {
	req.Header.Add("X-Xsrftoken", xsrfToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
}

func emptyJSONIOReader() io.Reader {
	return bytes.NewReader([]byte(`{}`))
}
