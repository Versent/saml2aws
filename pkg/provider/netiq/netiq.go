package netiq

import (
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
)

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

func (nc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
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
	debugResponse(samlRes)

	samlAssertion, err := nc.extractSAMLAssertion(samlRes)
	if err != nil {
		return "", errors.Wrap(err, "error extracting saml assertion from saml response")
	}
	return samlAssertion, nil
}

func (nc *Client) getAppPortalLoginForm(loginDetails *creds.LoginDetails) (*http.Response, error) {
	return nc.client.Get(loginDetails.URL + "/nidp/app/login?sid=0&option=credential")
}

func debugResponse(resp *http.Response) {
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err == nil {
		logrus.
			WithField("body", doc.Text()).
			WithFields(logrus.Fields{"Status": resp.Status}).Debug("HTTP Resp Body (DEBUG)")
	}
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
	return nc.client.Get(loginDetails.URL + "/nidp/saml2/idpsend?PID=STSPv8a5kc")
}

func (nc *Client) extractSAMLAssertion(resp *http.Response) (string, error) {
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "Can't extract SAML assertion from")
	}
	samlAssertion, ok := doc.Find("input[name=\"SAMLResponse\"]").Attr("value")
	if !ok {
		return "", errors.Wrap(err, "No SAML assertion found in response")
	}
	return samlAssertion, nil
}
