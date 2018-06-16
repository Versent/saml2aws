package googleapps

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "googleapps")

// Client wrapper around Google Apps.
type Client struct {
	client *provider.HTTPClient
}

// New create a new Google Apps Client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into Google Apps and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	// Get the first page
	authURL, authForm, err := kc.loadFirstPage(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error loading first page")
	}

	authForm.Set("Email", loginDetails.Username)

	passwordURL, _, err := kc.loadLoginPage(authURL, loginDetails.URL, authForm)
	if err != nil {
		return "", errors.Wrap(err, "error loading login page")
	}

	logger.Debugf("loginURL: %s", passwordURL)

	authForm.Set("Passwd", loginDetails.Password)
	authForm.Set("rawidentifier", loginDetails.Username)

	responseDoc, err := kc.loadChallengePage(passwordURL, authURL, authForm)
	if err != nil {
		return "", errors.Wrap(err, "error loading challenge page")
	}

	// extract the saml assertion
	samlAssertion := mustFindInputByName(responseDoc, "SAMLResponse")
	if samlAssertion == "" {
		return "", errors.New("page is missing saml assertion")
	}

	return samlAssertion, nil
}

func (kc *Client) loadFirstPage(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	req, err := http.NewRequest("GET", loginDetails.URL, nil)
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving login form from idp")
	}

	res, err := kc.client.Do(req)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to make request to login form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "error parsing first page html document")
	}

	authForm, submitURL, err := extractInputsByFormID(doc, "gaia_loginform")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build login form data")
	}

	postForm := url.Values{
		"bgresponse":      []string{"js_disabled"},
		"checkConnection": []string{""},
		"checkedDomains":  []string{"youtube"},
		"continue":        []string{authForm.Get("continue")},
		"gxf":             []string{authForm.Get("gxf")},
		"identifier-captcha-input": []string{""},
		"identifiertoken":          []string{""},
		"identifiertoken_audio":    []string{""},
		"ltmpl":                    []string{"popup"},
		"oauth":                    []string{"1"},
		"Page":                     []string{authForm.Get("Page")},
		"Passwd":                   []string{""},
		"PersistentCookie":         []string{"yes"},
		"ProfileInformation":       []string{""},
		"pstMsg":                   []string{"0"},
		"sarp":                     []string{"1"},
		"scc":                      []string{"1"},
		"SessionState":             []string{authForm.Get("SessionState")},
		"signIn":                   []string{authForm.Get("signIn")},
		"_utf8":                    []string{authForm.Get("_utf8")},
		"GALX":                     []string{authForm.Get("GALX")},
	}

	return submitURL, postForm, err
}

func (kc *Client) loadLoginPage(submitURL string, referer string, authForm url.Values) (string, url.Values, error) {

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", nil, errors.Wrap(err, "error retrieving login form")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)

	res, err := kc.client.Do(req)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to make request to login form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return "", nil, errors.Wrap(err, "error parsing login page html document")
	}

	loginForm, loginURL, err := extractInputsByFormID(doc, "gaia_loginform")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build login form data")
	}

	return loginURL, loginForm, err
}

func (kc *Client) loadChallengePage(submitURL string, referer string, authForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make request to login form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing login page html document")
	}

	errMsg := mustFindErrorMsg(doc)

	if errMsg != "" {
		return nil, errors.New("Invalid username or password")
	}

	secondFactorHeader := "This extra step shows it’s really you trying to sign in"

	// have we been asked for 2-Step Verification
	if extractNodeText(doc, "h2", secondFactorHeader) != "" {

		responseForm, secondActionURL, err := extractInputsByFormID(doc, "challenge")
		if err != nil {
			return nil, errors.Wrap(err, "unable to extract challenge form")
		}

		logrus.Debugf("secondActionURL: %s", secondActionURL)

		u, _ := url.Parse(submitURL)
		u.Path = secondActionURL // we are just updating the path with the action as it is a relative path

		switch {
		case strings.Contains(secondActionURL, "challenge/totp/"): // handle TOTP challenge

			var token = prompter.RequestSecurityCode("000000")

			responseForm.Set("Pin", token)

			return kc.loadResponsePage(u.String(), submitURL, responseForm)
		case strings.Contains(secondActionURL, "challenge/ipp/"): // handle SMS challenge
			var token = prompter.StringRequired("Enter SMS token: G-")

			responseForm.Set("Pin", token)

			return kc.loadResponsePage(u.String(), submitURL, responseForm)
		}

		return nil, errors.Errorf("unsupported second factor: %s", secondActionURL)
	}

	return doc, nil

}

func (kc *Client) loadResponsePage(submitURL string, referer string, responseForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(responseForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving response page")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", submitURL)

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make request to login form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing login page html document")
	}

	return doc, nil
}

func mustFindInputByName(doc *goquery.Document, name string) string {

	var fieldValue string

	q := fmt.Sprintf(`input[name="%s"]`, name)

	doc.Find(q).Each(func(i int, s *goquery.Selection) {
		val, ok := s.Attr("value")
		if !ok {
			log.Fatal("unable to locate field value")
		}
		fieldValue = val
	})

	return fieldValue
}

func mustFindErrorMsg(doc *goquery.Document) string {
	var fieldValue string
	doc.Find(".error-msg").Each(func(i int, s *goquery.Selection) {
		fieldValue = s.Text()

	})
	return fieldValue
}

func extractInputsByFormID(doc *goquery.Document, formID string) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string

	query := fmt.Sprintf("form#%s", formID)

	//get action url
	doc.Find(query).Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	query = fmt.Sprintf("form#%s", formID)

	// extract form data to passthrough
	doc.Find(query).Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		logger.Info("name: ", name)
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		formData.Add(name, val)
	})

	return formData, actionURL, nil
}

func extractNodeText(doc *goquery.Document, tag, txt string) string {

	var res string

	doc.Find(tag).Each(func(i int, s *goquery.Selection) {
		if s.Text() == txt {
			res = s.Text()
		}
	})

	return res
}
