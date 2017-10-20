package dump

import (
	"net/http"
	"net/http/httputil"
)

func RequestString(req *http.Request) string {
	data, err := httputil.DumpRequest(req, false)

	if err != nil {
		return ""
	}

	return string(data)
}

func ResponseString(res *http.Response) string {
	data, err := httputil.DumpResponse(res, false)

	if err != nil {
		return ""
	}

	return string(data)
}
