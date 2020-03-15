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

// Client wrapper around KeyCloak.
type Client struct {
	client *provider.HTTPClient
	mfa    string
}

// New create a new KeyCloakClient
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

// Authenticate logs into KeyCloak and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	doc, loginURL, err := kc.getLoginForm(loginDetails.URL)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving login form from idp")
	}

	doc, homepageURL, err := kc.postLoginForm(loginDetails, doc, loginURL)
	if err != nil {
		return "", errors.Wrap(err, "error submitting login form")
	}

	if containsTotpForm(doc) {
		apiURL, sid, err := kc.postMfaInitForm(loginDetails, doc, homepageURL)
		if err != nil {
			return "", errors.Wrap(err, "error posting totp form")
		}

		token, err := kc.postPromptForm(loginDetails, apiURL, sid)
		if err != nil {
			return "", errors.Wrap(err, "error posting totp form")
		}

		doc, err = kc.postMfaFinishForm(token, homepageURL, doc)
		if err != nil {
			return "", errors.Wrap(err, "error posting totp form")
		}
	}

	var samlAssertion string

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		if name == "SAMLResponse" {
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

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error building initial request")
	}

	kc.client.DisableFollowRedirect()
	res, err := kc.client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error performing initial request")
	}
	kc.client.EnableFollowRedirect()

	redirect, err := res.Location()
	if err != nil {
		return nil, nil, errors.Wrap(err, "no login redirect in initial request")
	}

	req, err = http.NewRequest("GET", redirect.String(), nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error building login redirect request")
	}

	res, err = kc.client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error performing login redirect request")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build document from response")
	}

	return doc, redirect, nil
}

func (kc *Client) postLoginForm(loginDetails *creds.LoginDetails, doc *goquery.Document, target *url.URL) (*goquery.Document, *url.URL, error) {

	target, _ = url.Parse(target.String())
	target.ForceQuery = true
	target.RawQuery = ""

	authForm := url.Values{}
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateKeyCloakFormData(authForm, s, loginDetails)
	})

	req, err := http.NewRequest("POST", target.String(), strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	kc.client.DisableFollowRedirect()
	res, err := kc.client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error retrieving login form")
	}
	kc.client.EnableFollowRedirect()

	redirect, err := res.Location()
	if err != nil {
		return nil, nil, errors.Wrap(err, "no login redirect in initial request")
	}

	req, err = http.NewRequest("GET", redirect.String(), nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error building login redirect request")
	}

	res, err = kc.client.Do(req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error performing login redirect request")
	}

	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build document from response")
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
		return "", "", errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	query := req.URL.Query()
	query.Add("tx", signature)
	query.Add("parent", target.String())
	query.Add("v", "2.6")
	req.URL.RawQuery = query.Encode()

	kc.client.DisableFollowRedirect()
	res, err := kc.client.Do(req)
	if err != nil {
		return "", "", errors.Wrap(err, "error retrieving content")
	}
	kc.client.EnableFollowRedirect()

	redirect, err := res.Location()
	if err != nil {
		return "", "", errors.Wrap(err, "no login redirect in initial request")
	}

	return apiURL, redirect.Query().Get("sid"), nil
}

func (kc *Client) postPromptForm(loginDetails *creds.LoginDetails, apiURL string, sid string) (string, error) {
	reqURL := apiURL + "/frame/prompt"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building MFA request")
	}

	query := req.URL.Query()
	query.Add("sid", sid)
	req.URL.RawQuery = query.Encode()

	res, err := kc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving content")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
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
		return "", errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = kc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving content")
	}

	var data map[string]interface{}
	json.NewDecoder(res.Body).Decode(&data)

	authForm = url.Values{}
	authForm.Add("sid", sid)
	authForm.Add("txid", data["response"].(map[string]interface{})["txid"].(string))

	for i := 0; i < 2; i++ {
		reqURL = apiURL + "/frame/status"
		req, err = http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building MFA request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = kc.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error retrieving content")
		}
	}

	json.NewDecoder(res.Body).Decode(&data)

	authForm = url.Values{}
	authForm.Add("sid", sid)

	reqURL = apiURL + data["response"].(map[string]interface{})["result_url"].(string)
	req, err = http.NewRequest("POST", reqURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building MFA request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = kc.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving content")
	}

	json.NewDecoder(res.Body).Decode(&data)
	return data["response"].(map[string]interface{})["cookie"].(string), nil
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

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error performing login redirect request")
	}

	doc, err = goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	return doc, nil
}

func extractSubmitURL(doc *goquery.Document) (string, error) {

	var submitURL string

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		submitURL = action
	})

	if submitURL == "" {
		return "", fmt.Errorf("unable to locate form submit URL")
	}

	return submitURL, nil
}

func containsTotpForm(doc *goquery.Document) bool {
	// search totp field at Keycloak < 8.0.1
	totpIndex := doc.Find("iframe#duo_iframe").Index()

	if totpIndex != -1 {
		return true
	}

	return false
}

func updateKeyCloakFormData(authForm url.Values, s *goquery.Selection, user *creds.LoginDetails) {
	name, ok := s.Attr("name")
	// log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "username") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "password") {
		authForm.Add(name, user.Password)
	} else {
		// pass through any hidden fields
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		authForm.Add(name, val)
	}
}

func updateOTPFormData(otpForm url.Values, s *goquery.Selection, token string) {
	name, ok := s.Attr("name")
	// log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}

	lname := strings.ToLower(name)
	// search otp field at Keycloak >= 8.0.1
	if strings.Contains(lname, "totp") {
		otpForm.Add(name, token)
	} else if strings.Contains(lname, "otp") {
		otpForm.Add(name, token)
	}

}
