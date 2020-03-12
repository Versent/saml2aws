package netiq

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/page"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var logger = logrus.WithField("provider", "NetIQ")

type Client struct {
	client *provider.HTTPClient
}

// New creates a new external client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)
	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "Error building HTTP client")
	}
	return &Client{client: client}, nil

}

const samlURL = "/nidp/saml2/idpsend?PID=STSPv8a5kc"

func (nc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	req, err := http.NewRequest("GET", loginDetails.URL+samlURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "Error building request")
	}
	return nc.follow(req, loginDetails)
}

func (nc *Client) follow(req *http.Request, loginDetails *creds.LoginDetails) (string, error) {
	resp, err := nc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Failed to perform http request to "+req.URL.String())
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}
	if isSAMLResponse(doc) {
		return extractSAMLAssertion(doc)
	} else if resourcePath, isGetToContext := extractGetToContentUrl(doc); isGetToContext {
		newReq, err := buildGetToContentRequest(loginDetails.URL + resourcePath + "&uiDestination=contentDiv")
		if err != nil {
			return "", errors.Wrap(err, "Error building request")
		}
		return nc.follow(newReq, loginDetails)
	} else if resourceURL, isWinLocHref := extractWinLocHrefURL(doc); isWinLocHref {
		newReq, err := buildGetToContentRequest(resourceURL)
		if err != nil {
			return "", errors.Wrap(err, "Error building request")
		}
		return nc.follow(newReq, loginDetails)
	} else if form, isIDPLoginPass := extractIDPLoginPass(doc); isIDPLoginPass {
		form.Values.Set("Ecom_User_ID", loginDetails.Username)
		form.Values.Set("Ecom_Password", loginDetails.Password)
		newReq, err := form.BuildRequest()
		if err != nil {
			return "", errors.Wrap(err, "Error building request")
		}
		return nc.follow(newReq, loginDetails)
	} else if form, isIDPLoginRsa := extractIDPLoginRsa(doc); isIDPLoginRsa {
		token := prompter.StringRequired("Enter concatenated pin and token")
		form.Values.Set("Ecom_User_ID", loginDetails.Username)
		form.Values.Set("Ecom_Token", token)
		newReq, err := form.BuildRequest()
		if err != nil {
			return "", errors.Wrap(err, "Error building request")
		}
		return nc.follow(newReq, loginDetails)
	} else {
		return "", fmt.Errorf("unknown document type")
	}
}

func isSAMLResponse(doc *goquery.Document) bool {
	return doc.Find("input[name=\"SAMLResponse\"]").Size() == 1
}

func extractSAMLAssertion(doc *goquery.Document) (string, error) {
	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", fmt.Errorf("no SAML assertion in response")
	}
	logDocDetected("samlResponse", samlAssertion)
	return samlAssertion, nil
}

func extractGetToContentUrl(doc *goquery.Document) (string, bool) {
	script := doc.Find("body script:contains('getToContent')")
	if script.Size() != 1 {
		return "", false
	}
	re := regexp.MustCompile(`getToContent\('(.*)',.*\);`)
	match := re.FindStringSubmatch(strings.TrimSpace(script.Text()))
	if len(match) == 2 {
		logDocDetected("getToContent", match[1])
		return match[1], true
	} else {
		return "", false
	}
}

func extractWinLocHrefURL(doc *goquery.Document) (string, bool) {
	script := doc.Find("body script:contains('window.location.href')")
	if script.Size() != 1 {
		return "", false
	}
	re := regexp.MustCompile(`window.location.href='(.*)';`)
	match := re.FindStringSubmatch(strings.TrimSpace(script.Text()))
	if len(match) == 2 {
		logDocDetected("winLocHref", match[1])
		return match[1], true
	} else {
		return "", false
	}
}

func extractIDPLoginPass(doc *goquery.Document) (*page.Form, bool) {
	idpPoginForm := doc.Find("body form:has(input[name=\"Ecom_Password\"])")
	if idpPoginForm.Size() != 1 {
		return nil, false
	}
	action, exists := idpPoginForm.Attr("action")
	if !exists {
		return nil, false
	}
	logDocDetected("idpLoginPass", action)
	form := &page.Form{
		URL:    action,
		Method: "POST",
		Values: &url.Values{},
	}
	return form, true
}

func extractIDPLoginRsa(doc *goquery.Document) (*page.Form, bool) {
	idpPoginForm := doc.Find("body form:has(input[name=\"Ecom_Token\"])")
	if idpPoginForm.Size() != 1 {
		return nil, false
	}
	action, exists := idpPoginForm.Attr("action")
	if !exists {
		return nil, false
	}
	logDocDetected("idpLoginRsa", action)
	form := &page.Form{
		URL:    action,
		Method: "POST",
		Values: &url.Values{},
	}
	return form, true
}

func buildGetToContentRequest(resourceURL string) (*http.Request, error) {
	return http.NewRequest("GET", resourceURL, nil)
}

func logDocDetected(docType string, data string) {
	logDetect := logger
	if data != "" {
		logDetect = logDetect.WithField("docType", docType)
	}
	if data != "" {
		logDetect = logDetect.WithField("data", data)
	}
	logDetect.Debug("doc detect")
}
