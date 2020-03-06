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
	"io/ioutil"
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
	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "Error building HTTP client")
	}
	return &Client{client: client}, nil

}

const isFollow = true
const samlURL = "/nidp/saml2/idpsend?PID=STSPv8a5kc"

func (nc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	if isFollow {
		req, err := http.NewRequest("GET", loginDetails.URL+samlURL, nil)
		if err != nil {
			return "", errors.Wrap(err, "Error building request")
		}
		return nc.follow(req, loginDetails)
	} else {
		return nc.staticFlow(loginDetails)
	}
}

func (nc *Client) follow(req *http.Request, loginDetails *creds.LoginDetails) (string, error) {
	debugRequest(req)
	resp, err := nc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "Failed to perform http request to "+req.URL.String())
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}
	debugResponse(resp)
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

func extractGetToContentUrl(doc *goquery.Document) (string, bool) {
	script := doc.Find("body script:contains('getToContent')")
	if script.Size() != 1 {
		return "", false
	}
	re := regexp.MustCompile(`getToContent\('(.*)',.*\);`)
	match := re.FindStringSubmatch(strings.TrimSpace(script.Text()))
	if len(match) == 2 {
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

func (nc *Client) staticFlow(loginDetails *creds.LoginDetails) (string, error) {
	_, err := nc.getAppPortalLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error logging into Applications portal")
	}
	_, err = nc.loginToAppPortal(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error logging into Applications portal")
	}
	_, err = nc.getKerbToken(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error getting kerberos token")
	}
	_, err = nc.rsaAuth(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error performing rsa authentication")
	}
	samlRes, err := nc.getSAMLResponse(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error getting saml response")
	}

	doc, err := goquery.NewDocumentFromReader(samlRes.Body)
	if err != nil {
		return "", errors.Wrap(err, "Can't extract SAML assertion from")
	}
	debugResponse(samlRes)
	samlAssertion, err := extractSAMLAssertion(doc)
	if err != nil {
		return "", errors.Wrap(err, "error extracting saml assertion from saml response")
	}
	return samlAssertion, nil
}

func (nc *Client) getAppPortalLoginForm(loginDetails *creds.LoginDetails) (*http.Response, error) {
	return nc.client.Get(loginDetails.URL + "/nidp/app/login?sid=0&option=credential")
}

func debugResponse(resp *http.Response) {
	var respBodyStr = ""
	if resp.Body != nil {
		respBody, _ := ioutil.ReadAll(resp.Body)
		respBodyStr = string(respBody)
	}
	logger.
		WithField("RequestMethod", resp.Request.Method).
		WithField("RequestURL", resp.Request.URL).
		WithField("ResponseBody", respBodyStr).
		WithField("ResponseStatus", resp.Status).
		Debug("HTTP Response (DEBUG)")
}

func debugRequest(req *http.Request) {
	var reqBodyStr = ""
	if req.Body != nil {
		reqBody, _ := ioutil.ReadAll(req.Body)
		reqBodyStr = string(reqBody)
	}
	logger.
		WithField("Method", req.Method).
		WithField("URL", req.URL).
		WithField("Body", reqBodyStr).
		Debug("HTTP Request (DEBUG)")
}

func logDocDetected(docType string) {
	logger.
		WithField("type", docType).
		Debug("doc detect")
}

func (nc *Client) loginToAppPortal(loginDetails *creds.LoginDetails) (*http.Response, error) {
	form := page.Form{
		Method: "POST",
		URL:    loginDetails.URL + "/nidp/app/login?sid=0",
		Values: &url.Values{}}
	form.Values.Add("option", "credential")
	form.Values.Add("Ecom_User_ID", loginDetails.Username)
	form.Values.Add("Ecom_Password", loginDetails.Password)
	req, err := form.BuildRequest()
	if err != nil {
		return nil, err
	}
	return nc.client.Do(req)
}

func (nc *Client) getKerbToken(loginDetails *creds.LoginDetails) (*http.Response, error) {
	return nc.client.Get(loginDetails.URL + "/nidp/app/login?id=contract_kerb&sid=0&option=credential")
}

func (nc *Client) rsaAuth(loginDetails *creds.LoginDetails) (*http.Response, error) {
	token := prompter.StringRequired("Enter concatenated pin and token")
	form := page.Form{
		Method: "POST",
		URL:    loginDetails.URL + "/nidp/app/login?sid=0",
		Values: &url.Values{}}
	form.Values.Add("option", "credential")
	form.Values.Add("Ecom_User_ID", loginDetails.Username)
	form.Values.Add("Ecom_Token", token)
	req, err := form.BuildRequest()
	if err != nil {
		return nil, err
	}
	return nc.client.Do(req)
}

func (nc *Client) getSAMLResponse(loginDetails *creds.LoginDetails) (*http.Response, error) {
	return nc.client.Get(loginDetails.URL + samlURL)
}

func extractSAMLAssertion(doc *goquery.Document) (string, error) {
	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", fmt.Errorf("no SAML assertion in response")
	}
	return samlAssertion, nil
}
