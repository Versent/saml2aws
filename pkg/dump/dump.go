package dump

import (
	"net/http"
	"net/http/httputil"
)

// RequestString helper method to dump the http request
func RequestString(req *http.Request) string {
	data, err := httputil.DumpRequest(req, false)

	if err != nil {
		return ""
	}

	return string(data)
}

// ResponseString helper method to dump the http response
func ResponseString(res *http.Response) string {
	data, err := httputil.DumpResponse(res, false)

	if err != nil {
		return ""
	}

	return string(data)
}
