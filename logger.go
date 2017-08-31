package saml2aws

import (
	"net/http"
	"net/http/httputil"
)

func requestString(req *http.Request) string {
	data, err := httputil.DumpRequest(req, false)

	if err != nil {
		return ""
	}

	return string(data)
}
