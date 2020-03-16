package duo

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

// Client wrapper around the Duo Access Gateway.
type Client struct {
	client *provider.HTTPClient
	mfa    string
}

type duoResponse interface {
	GetStat() string
}

type baseDuoResponse struct {
	Stat string `json:"stat"`
}

type duoResultResponse struct {
	Response struct {
		Cookie string `json:"cookie"`
	} `json:"response"`

	baseDuoResponse
}

type duoStatusResponse struct {
	Response struct {
		Result     string `json:"result"`
		ResultURL  string `json:"result_url"`
		Status     string `json:"status"`
		StatusCode string `json:"status_code"`
	} `json:"response"`

	baseDuoResponse
}

type duoSubmitionResponse struct {
	Response struct {
		TxtID string `json:"txid"`
	} `json:"response"`

	baseDuoResponse
}

// New create a new DuoClient
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
		mfa:    idpAccount.MFA,
	}, nil
}

// Authenticate logs into Duo Access Gateway and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	doc, loginURL, err := kc.getLoginForm(loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form from idp")
	}

	doc, homepageURL, err := kc.postLoginForm(loginDetails, doc, loginURL)
	if err != nil {
		return "", errors.Wrap(err, "error submitting login form to idp")
	}

	if containsDuoIFrame(doc) {
		apiURL, sid, err := kc.postMfaInitForm(loginDetails, doc, homepageURL)
		if err != nil {
			return "", errors.Wrap(err, "error initializing mfa form")
		}

		token, err := kc.postPromptForm(loginDetails, apiURL, sid)
		if err != nil {
			return "", errors.Wrap(err, "error submitting mfa prompt")
		}

		doc, err = kc.postMfaFinishForm(token, homepageURL, doc)
		if err != nil {
			return "", errors.Wrap(err, "error finalizing mfa form")
		}
	}

	var samlAssertion string

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}

		lname := strings.ToLower(name)
		if lname == "samlresponse" {
			val, ok := s.Attr("value")
			if !ok {
				log.Fatalf("unable to locate saml assertion value")
			}
			samlAssertion = val
		}
	})

	if samlAssertion == "" {
		log.Fatalf("unable to locate IDP authentication form submit URL")
	}

	return samlAssertion, nil
}

func (kc *Client) getLoginForm(target string) (*goquery.Document, *url.URL, error) {

	redirect, err := getRedirectLocationFromURL(kc.client, target)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to retrieve login form redirect")
	}

	doc, err := getDocumentFromURL(kc.client, redirect.String())
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to retrive login form")
	}

	return doc, redirect, nil
}

func (kc *Client) postLoginForm(loginDetails *creds.LoginDetails, doc *goquery.Document, target *url.URL) (*goquery.Document, *url.URL, error) {

	target, _ = url.Parse(target.String())
	target.ForceQuery = true
	target.RawQuery = ""

	authForm := url.Values{}
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}

		if name == "username" {
			authForm.Add(name, loginDetails.Username)
		} else if name == "password" {
			authForm.Add(name, loginDetails.Password)
		} else {
			val, ok := s.Attr("value")
			if !ok {
				authForm.Set(name, "")
			}
			authForm.Add(name, val)
		}
	})

	req, err := http.NewRequest("POST", target.String(), strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	redirect, err := getRedirectLocationFromRequest(kc.client, req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to retrieve login form sumbission redirect")
	}

	doc, err = getDocumentFromURL(kc.client, redirect.String())
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to retrieve multi-factor prompt wrapper")
	}

	return doc, redirect, nil
}

func (kc *Client) postMfaInitForm(loginDetails *creds.LoginDetails, doc *goquery.Document, target *url.URL) (string, string, error) {

	var host string
	var signature string
	doc.Find("iframe#duo_iframe").Each(func(i int, s *goquery.Selection) {
		host, _ = s.Attr("data-host")
		signature, _ = s.Attr("data-sig-request")
		signature = strings.Split(signature, ":")[0]
	})

	authForm := url.Values{}
	authForm.Add("tx", signature)
	authForm.Add("parent", target.String())

	apiURL := "https://" + host
	reqURL := apiURL + "/frame/web/v1/auth"
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", "", errors.Wrap(err, "error creating multi-factor init request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	query := req.URL.Query()
	query.Add("tx", signature)
	query.Add("parent", target.String())
	query.Add("v", "2.6")
	req.URL.RawQuery = query.Encode()

	redirect, err := getRedirectLocationFromRequest(kc.client, req)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to retrieve multi-factory init redirect")
	}

	return apiURL, redirect.Query().Get("sid"), nil
}

func (kc *Client) postPromptForm(loginDetails *creds.LoginDetails, apiURL string, sid string) (string, error) {
	reqURL := apiURL + "/frame/prompt"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error creating multi-factor prompt form request")
	}

	query := req.URL.Query()
	query.Add("sid", sid)
	req.URL.RawQuery = query.Encode()

	doc, err := getDocumentFromRequest(kc.client, req)
	if err != nil {
		return "", errors.Wrap(err, "failed to retrieve multi-factor prompt form")
	}

	authForm := url.Values{}
	factors := make([]string, 0)
	doc.Find("form#login-form input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}

		val, ok := s.Attr("value")
		if !ok {
			authForm.Set(name, "")
		}

		if name == "factor" {
			factors = append(factors, val)
		} else {
			authForm.Add(name, val)
		}
	})

	if strings.ToUpper(kc.mfa) != "AUTO" {
		authForm.Add("factor", kc.mfa)
	} else if len(factors) == 1 {
		authForm.Add("factor", factors[0])
	} else {
		idx := prompter.Choose("Select which MFA option to use", factors)
		authForm.Add("factor", factors[idx])
	}

	if authForm.Get("factor") == "Passcode" {
		passcode := loginDetails.MFAToken
		if passcode == "" {
			passcode = prompter.RequestSecurityCode("000000")
		}

		authForm.Set("passcode", passcode)
	}

	devices := make(map[string]string)
	doc.Find("form#login-form select[name=\"device\"] option").Each(func(i int, s *goquery.Selection) {
		val, ok := s.Attr("value")
		if !ok {
			return
		}

		devices[val] = s.Text()
	})

	if len(devices) == 1 {
		for k := range devices {
			authForm.Add("device", k)
			break
		}
	} else {
		options := make([]string, 0, len(devices))
		for _, v := range devices {
			options = append(options, v)
		}

		idx := prompter.Choose("Select which MFA device to use", options)
		for k, v := range devices {
			if v == options[idx] {
				authForm.Add("device", devices[k])
				break
			}
		}
	}

	req, err = http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error creating multi-factor form submission request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var submitResp duoSubmitionResponse
	err = getJSONFromRequest(kc.client, req, &submitResp)
	if err != nil {
		return "", errors.Wrap(err, "failed to submit multi-factor form")
	}

	authForm = url.Values{}
	authForm.Add("sid", sid)
	authForm.Add("txid", submitResp.Response.TxtID)

	var statusResp duoStatusResponse
	for i := 0; i < 3; i++ {
		reqURL = apiURL + "/frame/status"
		req, err = http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error creating multi-factor status request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		err = getJSONFromRequest(kc.client, req, &statusResp)
		if err != nil {
			return "", errors.Wrap(err, "failed to retrieve multi-factor status")
		}

		if statusResp.Response.Status != "" {
			fmt.Printf("%s\n", statusResp.Response.Status)
		}

		if statusResp.Response.StatusCode != "pushed" {
			break
		}
	}

	if statusResp.Response.Result != "SUCCESS" {
		return "", errors.Errorf("multi-factor authentication failed: %s", statusResp.Response.StatusCode)
	}

	authForm = url.Values{}
	authForm.Add("sid", sid)

	reqURL = apiURL + statusResp.Response.ResultURL
	req, err = http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error creating multi-factor result request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	var resultResp duoResultResponse
	err = getJSONFromRequest(kc.client, req, &resultResp)
	if err != nil {
		return "", errors.Wrap(err, "failed to retrieve multi-factor result")
	}

	return resultResp.Response.Cookie, nil
}

func (kc *Client) postMfaFinishForm(cookie string, target *url.URL, doc *goquery.Document) (*goquery.Document, error) {
	var signature string
	doc.Find("iframe#duo_iframe").Each(func(i int, s *goquery.Selection) {
		signature, _ = s.Attr("data-sig-request")
		signature = strings.Split(signature, ":")[1]
	})

	authForm := url.Values{}
	doc.Find("form#duo_form input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}

		val, ok := s.Attr("value")
		if !ok {
			return
		}

		authForm.Add(name, val)
	})
	authForm.Add("sig_response", cookie+":"+signature)

	req, err := http.NewRequest("POST", target.String(), strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building login redirect request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	doc, err = getDocumentFromRequest(kc.client, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	return doc, nil
}

func (resp *baseDuoResponse) GetStat() string {
	return resp.Stat
}

func containsDuoIFrame(doc *goquery.Document) bool {
	iframeIndex := doc.Find("iframe#duo_iframe").Index()

	if iframeIndex != -1 {
		return true
	}

	return false
}

func getDocumentFromRequest(client *provider.HTTPClient, req *http.Request) (*goquery.Document, error) {
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error performing request")
	}

	return goquery.NewDocumentFromResponse(res)
}

func getDocumentFromURL(client *provider.HTTPClient, url string) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error creating request")
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error performing request")
	}

	return goquery.NewDocumentFromResponse(res)
}

func getJSONFromRequest(client *provider.HTTPClient, req *http.Request, v duoResponse) error {
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "error performing request")
	}

	err = json.NewDecoder(res.Body).Decode(v)
	if err != nil {
		return errors.Wrap(err, "failed to process response as JSON")
	} else if v.GetStat() != "OK" {
		return errors.Errorf("request returned error status: %s", v.GetStat())
	}

	return nil
}

func getRedirectLocationFromRequest(client *provider.HTTPClient, req *http.Request) (*url.URL, error) {
	client.DisableFollowRedirect()
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error performing request")
	}
	client.EnableFollowRedirect()

	return res.Location()
}

func getRedirectLocationFromURL(client *provider.HTTPClient, url string) (*url.URL, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error creating request")
	}

	client.DisableFollowRedirect()
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error performing request")
	}
	client.EnableFollowRedirect()

	return res.Location()
}
