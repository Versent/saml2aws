package dump

import (
	"net/http"
	"net/http/httputil"
	"os"
)

// RequestString helper method to dump the http request
func RequestString(req *http.Request) string {
	data, err := httputil.DumpRequestOut(req, ContentEnable())

	if err != nil {
		return ""
	}

	return string(data)
}

// ResponseString helper method to dump the http response
func ResponseString(res *http.Response) string {
	data, err := httputil.DumpResponse(res, ContentEnable())

	if err != nil {
		return ""
	}

	return string(data)
}

// ContentEnable enable dumping of request / response content
func ContentEnable() bool {
	return os.Getenv("DUMP_CONTENT") == "true"
}
