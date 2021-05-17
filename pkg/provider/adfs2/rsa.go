package adfs2

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/dump"
	"github.com/versent/saml2aws/v2/pkg/prompter"
)

// Authenticate authenticate the user using the supplied login details
func (ac *Client) authenticateRsa(loginDetails *creds.LoginDetails) (string, error) {

	authSubmitURL, authForm, err := ac.getLoginForm(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form from idp")
	}

	doc, err := ac.postLoginForm(authSubmitURL, authForm)
	if err != nil {
		return "", errors.Wrap(err, "error posting login form to idp")
	}

	passcodeForm, passcodeActionURL, err := extractFormData(doc)
	if err != nil {
		return "", errors.Wrap(err, "error extractign login data")
	}

	/**
	 * RSAv2 requires an additional POST to establish a context
	 * https://github.com/torric1/AWSCLI-MFA-RSAv2
	 * https://gist.github.com/jgard/17262e0fc073c82bc7930db2f5603446
	 */
	if passcodeForm.Get("AuthMethod") == "SecurIDv2Authentication" {
		doc, err = ac.postPasscodeForm(passcodeActionURL, passcodeForm)
		if err != nil {
			return "", errors.Wrap(err, "error posting passcode form")
		}
	}

	passcodeForm, passcodeActionURL, err = extractFormData(doc)
	if err != nil {
		return "", errors.Wrap(err, "error extracting mfa form data")
	}

	token := prompter.Password("Enter passcode")

	passcodeForm.Set("ChallengeQuestionAnswer", token)
	passcodeForm.Set("Passcode", token)
	passcodeForm.Del("submit")

	doc, err = ac.postPasscodeForm(passcodeActionURL, passcodeForm)
	if err != nil {
		return "", errors.Wrap(err, "error posting login form to idp")
	}

	rsaForm, rsaActionURL, err := extractFormData(doc)
	if err != nil {
		return "", errors.Wrap(err, "error extracting rsa form data")
	}

	if rsaForm.Get("SAMLResponse") == "" {
		nextCode := prompter.Password("Enter nextCode")

		rsaForm.Set("ChallengeQuestionAnswer", token)
		rsaForm.Set("NextCode", nextCode)
		rsaForm.Del("submit")

		doc, err = ac.postRSAForm(rsaActionURL, rsaForm)
		if err != nil {
			return "", errors.Wrap(err, "error posting rsa form")
		}
	}
	return extractSamlAssertion(doc)
}

func (ac *Client) postLoginForm(authSubmitURL string, authForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	logger.WithField("authSubmitURL", authSubmitURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("status", res.StatusCode).WithField("authSubmitURL", authSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	return doc, nil
}

func (ac *Client) getLoginForm(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	adfs2Url := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)

	req, err := http.NewRequest("GET", adfs2Url, nil)
	if err != nil {
		return "", nil, err
	}

	res, err := ac.client.Do(req)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("status", res.StatusCode).WithField("url", loginDetails.URL).WithField("res", dump.ResponseString(res)).Debug("GET")

	// Extract the form and actionURL from the previous response

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "error extracting response data")
	}
	authForm, authSubmitURL, err := extractFormData(doc)
	if err != nil {
		return "", nil, errors.Wrap(err, "error extracting login data")
	}

	authForm.Set("UserName", loginDetails.Username)
	authForm.Set("Password", loginDetails.Password)

	return authSubmitURL, authForm, nil
}

func (ac *Client) postPasscodeForm(passcodeActionURL string, passcodeForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", passcodeActionURL, strings.NewReader(passcodeForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	logger.WithField("actionURL", passcodeActionURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("status", res.StatusCode).WithField("passcodeActionURL", passcodeActionURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	return doc, nil
}

func (ac *Client) postRSAForm(rsaSubmitURL string, form url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", rsaSubmitURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building authentication request")
	}

	logger.WithField("rsaSubmitURL", rsaSubmitURL).WithField("req", dump.RequestString(req)).Debug("POST")

	res, err := ac.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	logger.WithField("status", res.StatusCode).WithField("rsaSubmitURL", rsaSubmitURL).WithField("res", dump.ResponseString(res)).Debug("POST")

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving body")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "error parsing document")
	}

	return doc, nil
}

func extractFormData(doc *goquery.Document) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string

	//get action url
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// extract form data to passthrough
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		val, ok := s.Attr("value")
		if !ok || len(val) == 0 {
			return
		}
		formData.Set(name, val)
	})

	return formData, actionURL, nil
}
