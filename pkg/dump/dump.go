package dump

import (
	"net/http"
	"net/http/httputil"
	"os"
)

// RequestString helper method to dump the http request
func RequestString(req *http.Request) string {
	data, err := httputil.DumpRequest(req, dumpContentEnable())

	if err != nil {
		return ""
	}

	return string(data)
}

// ResponseString helper method to dump the http response
func ResponseString(res *http.Response) string {
	data, err := httputil.DumpResponse(res, dumpContentEnable())

	if err != nil {
		return ""
	}

	return string(data)
}

func dumpContentEnable() bool {
	return os.Getenv("DUMP_CONTENT") == "true"
}
