package googleapps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	passwordURL, _, err := kc.loadLoginPage(authURL+"?hl=en&loc=US", loginDetails.URL+"&hl=en&loc=US", authForm)
	if err != nil {
		return "", errors.Wrap(err, "error loading login page")
	}

	logger.Debugf("loginURL: %s", passwordURL)

	authForm.Set("Passwd", loginDetails.Password)
	authForm.Set("rawidentifier", loginDetails.Username)

	responseDoc, err := kc.loadChallengePage(passwordURL+"?hl=en&loc=US", authURL, authForm)
	if err != nil {
		return "", errors.Wrap(err, "error loading challenge page")
	}

	captchaFound := responseDoc.Find("#logincaptcha")

	for captchaFound != nil && captchaFound.Length() > 0 {

		captchaImgDiv := responseDoc.Find(".captcha-img")
		captchaPictureURL, found := goquery.NewDocumentFromNode(captchaImgDiv.Children().Nodes[0]).Attr("src")

		if !found {
			return "", errors.New("captcha image not found but requested")
		}

		fmt.Println("Open this link in a browser:\n", captchaPictureURL)

		captcha := prompter.String("Captcha", "")

		captchaForm, captchaURL, err := extractInputsByFormID(responseDoc, "gaia_loginform")
		if err != nil {
			return "", errors.Wrap(err, "error extracting captcha")
		}

		logger.Debugf("captchaURL: %s", captchaURL)

		captchaForm.Set("Passwd", loginDetails.Password)
		captchaForm.Set("logincaptcha", captcha)

		responseDoc, err = kc.loadChallengePage(captchaURL+"?hl=en&loc=US", captchaURL, captchaForm)
		if err != nil {
			return "", errors.Wrap(err, "error loading challenge page")
		}

		captchaFound = responseDoc.Find("#logincaptcha")
	}

	samlAssertion := mustFindInputByName(responseDoc, "SAMLResponse")
	if samlAssertion == "" {
		return "", errors.New("page is missing saml assertion")
	}

	return samlAssertion, nil
}

func (kc *Client) loadFirstPage(loginDetails *creds.LoginDetails) (string, url.Values, error) {

	req, err := http.NewRequest("GET", loginDetails.URL+"&hl=en&loc=US", nil)
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
		"bgresponse":               []string{"js_disabled"},
		"checkConnection":          []string{""},
		"checkedDomains":           []string{"youtube"},
		"continue":                 []string{authForm.Get("continue")},
		"gxf":                      []string{authForm.Get("gxf")},
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
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Content-Language", "en-US")
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
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Content-Language", "en-US")
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
	secondFactorHeader2 := "This extra step shows that it’s really you trying to sign in"
	secondFactorHeaderJp := "2 段階認証プロセス"

	// have we been asked for 2-Step Verification
	if extractNodeText(doc, "h2", secondFactorHeader) != "" ||
		extractNodeText(doc, "h2", secondFactorHeader2) != "" ||
		extractNodeText(doc, "h1", secondFactorHeaderJp) != "" {

		responseForm, secondActionURL, err := extractInputsByFormID(doc, "challenge")
		if err != nil {
			return nil, errors.Wrap(err, "unable to extract challenge form")
		}

		logger.Debugf("secondActionURL: %s", secondActionURL)

		u, _ := url.Parse(submitURL)
		u.Path = secondActionURL // we are just updating the path with the action as it is a relative path

		switch {
		case strings.Contains(secondActionURL, "challenge/totp/"): // handle TOTP challenge

			var token = prompter.RequestSecurityCode("000000")

			responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(u.String(), submitURL, responseForm)
		case strings.Contains(secondActionURL, "challenge/ipp/"): // handle SMS challenge

			var token = prompter.StringRequired("Enter SMS token: G-")

			responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(u.String(), submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/sk/"): // handle u2f challenge
			facet := u.Scheme + "://" + u.Host
			challengeNonce := responseForm.Get("id-challenge")
			appId, data := extractKeyHandles(doc, challengeNonce)
			u2fClient, err := NewU2FClient(challengeNonce, appId, facet, data[0], &U2FDeviceFinder{})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to prompt for second factor.")
			}

			response, err := u2fClient.ChallengeU2F()
			if err != nil {
				return nil, errors.Wrap(err, "Second factor failed.")
			}

			responseForm.Set("id-assertion", response)
			responseForm.Set("TrustDevice", "on")

			return kc.loadResponsePage(u.String(), submitURL, responseForm)
		case strings.Contains(secondActionURL, "challenge/az/"): // handle phone challenge

			dataAttrs := extractDataAttributes(doc, "div[data-context]", []string{"data-context", "data-gapi-url", "data-tx-id", "data-api-key", "data-tx-lifetime"})

			logger.Debugf("prompt with data values: %+v", dataAttrs)

			waitValues := map[string]string{
				"txId": dataAttrs["data-tx-id"],
			}

			fmt.Println("Open the Google App, and tap 'Yes' on the prompt to sign in")

			_, err := kc.postJSON(fmt.Sprintf("https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key=%s", dataAttrs["data-api-key"]), waitValues, submitURL)
			if err != nil {
				return nil, errors.Wrap(err, "unable to extract post wait tx form")
			}

			// responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(u.String(), submitURL, responseForm)
		}

		skipResponseForm, skipActionURL, err := extractInputsByFormQuery(doc, `[action$="skip"]`)
		if err != nil {
			return nil, errors.Wrap(err, "unable to extract skip form")
		}

		if skipActionURL == "" {
			return nil, errors.Errorf("unsupported second factor: %s", secondActionURL)
		}

		u.Path = skipActionURL

		return kc.loadAlternateChallengePage(u.String(), submitURL, skipResponseForm)

	}

	return doc, nil

}

func (kc *Client) loadAlternateChallengePage(submitURL string, referer string, authForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Content-Language", "en-US")
	req.Header.Set("Referer", referer)

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make request to login form")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing login page html document")
	}

	var challengeEntry string

	doc.Find("form[data-challengeentry]").EachWithBreak(func(i int, s *goquery.Selection) bool {
		action, ok := s.Attr("action")
		if !ok {
			return true
		}

		if strings.Contains(action, "challenge/totp/") ||
			strings.Contains(action, "challenge/ipp/") ||
			strings.Contains(action, "challenge/az/") {

			challengeEntry, _ = s.Attr("data-challengeentry")
			return false
		}

		return true
	})

	if challengeEntry == "" {
		return nil, errors.New("unable to find supported second factor")
	}

	query := fmt.Sprintf(`[data-challengeentry="%s"]`, challengeEntry)
	responseForm, newActionURL, err := extractInputsByFormQuery(doc, query)
	if err != nil {
		return nil, errors.Wrap(err, "unable to extract challenge form")
	}

	u, _ := url.Parse(submitURL)
	u.Path = newActionURL

	return kc.loadChallengePage(u.String(), submitURL, responseForm)
}

func (kc *Client) postJSON(submitURL string, values map[string]string, referer string) (*http.Response, error) {

	data, _ := json.Marshal(values)

	req, err := http.NewRequest("POST", submitURL, bytes.NewReader(data))
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving login form")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Content-Language", "en-US")
	req.Header.Set("Referer", referer)

	res, err := kc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to post JSON")
	}

	return res, nil
}

func (kc *Client) loadResponsePage(submitURL string, referer string, responseForm url.Values) (*goquery.Document, error) {

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(responseForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving response page")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Content-Language", "en-US")
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
			logger.Fatal("unable to locate field value")
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
	return extractInputsByFormQuery(doc, fmt.Sprintf("#%s", formID))
}

func extractInputsByFormQuery(doc *goquery.Document, formQuery string) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string

	query := fmt.Sprintf("form%s", formQuery)

	//get action url
	doc.Find(query).Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	query = fmt.Sprintf("form%s", formQuery)

	// extract form data to passthrough
	doc.Find(query).Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		logger.Debugf("name: %s value: %s", name, val)
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

func extractDataAttributes(doc *goquery.Document, query string, attrsToSelect []string) map[string]string {

	dataAttrs := make(map[string]string)

	doc.Find(query).Each(func(_ int, sel *goquery.Selection) {
		for _, f := range attrsToSelect {
			if val, ok := sel.Attr(f); ok {
				dataAttrs[f] = val
			}
		}
	})

	return dataAttrs
}

func extractKeyHandles(doc *goquery.Document, challengeTxt string) (string, []string) {
	appId := ""
	keyHandles := []string{}
	result := map[string]interface{}{}
	doc.Find("div[jsname=C0oDBd]").Each(func(_ int, sel *goquery.Selection) {
		val, ok := sel.Attr("data-challenge-ui")
		if ok {
			firstIdx := strings.Index(val, "{")
			lastIdx := strings.LastIndex(val, "}")
			obj := []byte(val[firstIdx : lastIdx+1])
			json.Unmarshal(obj, &result)

			// Key handles
			for _, val := range result {
				list, ok := val.([]interface{})
				if !ok {
					continue
				}
				tmpId, stringList := filterKeyHandleList(list, challengeTxt)
				if tmpId != "" {
					appId = tmpId
				}
				if len(stringList) != 0 {
					keyHandles = append(keyHandles, stringList...)
				}
			}
		}
	})
	return appId, keyHandles
}

func filterKeyHandleList(list []interface{}, challengeTxt string) (string, []string) {
	appId := ""
	newList := []string{}
	for _, entry := range list {
		if entry == nil {
			continue
		}
		moreList, ok := entry.([]interface{})
		if ok {
			id, l := filterKeyHandleList(moreList, challengeTxt)
			if id != "" {
				appId = id
			}
			newList = append(newList, l...)
			continue
		}
		str, ok := entry.(string)
		if !ok {
			continue
		}
		if appId == "" {
			appId = isAppId(str)
		}
		if isKeyHandle(str, challengeTxt) {
			newList = append(newList, str)
		}
	}
	return appId, newList
}

func isKeyHandle(key, challengeTxt string) bool {
	_, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	return key != challengeTxt
}

func isAppId(val string) string {
	obj := map[string]interface{}{}
	err := json.Unmarshal([]byte(val), &obj)
	if err != nil {
		return ""
	}
	appId, ok := obj["appid"].(string)
	if !ok {
		return ""
	}
	return appId
}
