package googleapps

import (
	"bufio"
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

var logger = logrus.WithField("provider", "googleapps")

var challengeTypeToCode = map[string]string{
	"39": "dp",
	"5":  "ootp",
	"6":  "totp",
	"9":  "ipp",
	"53": "pk",
}

// Client wrapper around Google Apps.
type Client struct {
	provider.ValidateBase

	client *provider.HTTPClient
}

// New create a new Google Apps Client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client: client,
	}, nil
}

// Authenticate logs into Google Apps and returns a SAML response
func (kc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	// Copy and freeze preferred challenges to ensure loginDetails remains immutable
	var preferredChallenges []string
	if len(loginDetails.GoogleChallenges) > 0 {
		preferredChallenges = make([]string, len(loginDetails.GoogleChallenges))
		copy(preferredChallenges, loginDetails.GoogleChallenges)
	}

	// Get the first page
	authURL, authForm, err := kc.loadFirstPage(loginDetails)
	if err != nil {
		return "", errors.Wrap(err, "error loading first page")
	}

	// Google supports only JavaScript-enabled clients
	authForm.Set("bgresponse", "js_enabled")

	authForm.Set("Email", loginDetails.Username)

	// Post email address w/o password, then Get the password-input page
	passwordURL, passwordForm, err := kc.loadLoginPage(authURL+"?hl=en&loc=US", loginDetails.URL+"&hl=en&loc=US", authForm)
	if err != nil {
		//if failed, try with "identifier"
		authForm.Set("Email", "") // Clear previous key
		authForm.Set("identifier", loginDetails.Username)
		passwordURL, passwordForm, err = kc.loadLoginPage(authURL+"?hl=en&loc=US", loginDetails.URL+"&hl=en&loc=US", authForm)

		if err != nil {
			return "", errors.Wrap(err, "error loading login page")
		}
	}

	logger.Debugf("loginURL: %s", passwordURL)

	passwordForm.Set("Passwd", loginDetails.Password)
	passwordForm.Set("TrustDevice", "on")

	referingURL := passwordURL

	responseDoc, err := kc.loadChallengePage(passwordURL+"?hl=en&loc=US", referingURL, passwordForm, loginDetails, preferredChallenges...)
	if err != nil {
		return "", errors.Wrap(err, "error loading challenge page")
	}

	captchaInputIds := []string{
		"logincaptcha",
		"identifier-captcha-input",
		"captchaimg",
	}

	var captchaFound *goquery.Selection
	var captchaInputId string

	for _, v := range captchaInputIds {
		captchaFound = responseDoc.Find(fmt.Sprintf("#%s", v))
		if captchaFound != nil && captchaFound.Length() > 0 {
			captchaInputId = v
			break
		}
	}

	for captchaFound != nil && captchaFound.Length() > 0 {
		captchaImgDiv := responseDoc.Find(".captcha-img")
		if captchaImgDiv != nil {
			captchaImgDiv = responseDoc.Find("div[data-auto-init='CaptchaInput']")
			captchaInputId = "ca"
		}
		captchaPictureSrc, found := goquery.NewDocumentFromNode(captchaImgDiv.Children().Nodes[0]).Attr("src")

		if !found {
			return "", errors.New("captcha image not found but requested")
		}

		captchaPictureURL, err := generateFullURLIfRelative(captchaPictureSrc, passwordURL)
		if err != nil {
			return "", errors.Wrap(err, "error generating captcha image URL")
		}

		captcha, err := kc.tryDisplayCaptcha(captchaPictureURL)
		if err != nil {
			return "", err
		}

		captchaForm, captchaURL, err := extractInputsByFormID(responseDoc, "gaia_loginform", "challenge")
		if err != nil {
			return "", errors.Wrap(err, "error extracting captcha")
		}

		logger.Debugf("captchaURL: %s", captchaURL)

		_, captchaV1 := captchaForm["Passwd"]
		if captchaV1 {
			captchaForm.Set("Passwd", loginDetails.Password)
		}
		captchaForm.Set(captchaInputId, captcha)

		responseDoc, err = kc.loadChallengePage(captchaURL+"?hl=en&loc=US", captchaURL, captchaForm, loginDetails, preferredChallenges...)
		if err != nil {
			return "", errors.Wrap(err, "error loading challenge page")
		}

		captchaFound = responseDoc.Find(fmt.Sprintf("#%s", captchaInputId))
	}

	// New Captcha proceeds back to password page
	passwordBeingRequested := responseDoc.Find("#password")
	if passwordBeingRequested != nil && passwordBeingRequested.Length() > 0 {
		loginForm, loginURL, err := extractInputsByFormID(responseDoc, "challenge")
		if err != nil {
			return "", errors.Wrap(err, "error parsing password page after captcha")
		}

		loginForm.Set("Passwd", loginDetails.Password)

		responseDoc, err = kc.loadChallengePage(loginURL+"?hl=en&loc=US", loginURL, loginForm, loginDetails, preferredChallenges...)
		if err != nil {
			return "", errors.Wrap(err, "error loading challenge page")
		}
	}

	samlAssertion := mustFindInputByName(responseDoc, "SAMLResponse")
	if samlAssertion == "" {
		return "", createEmptySAMLAssertionError(responseDoc)
	}

	return samlAssertion, nil
}

func createEmptySAMLAssertionError(responseDoc *goquery.Document) error {
	if responseDoc.Selection.Find("#passwordError").Text() != "" {
		return errors.New("Password error")
	}

	text := responseDoc.Selection.Find("section.aN1Vld").Text()

	if strings.Contains(text, "Google sent a notification") {
		return errors.New("Please confirm the notification sent by Google on your device before pressing Enter")
	} else if strings.Contains(text, "Too many failed attempts") {
		return errors.New("Too many failed attempts")
	} else if text != "" {
		return errors.New("Because of your organization settings, you must set-up 2-Step Verification in your account")
	}

	return errors.New("page is missing saml assertion")
}

func (kc *Client) tryDisplayCaptcha(captchaPictureURL string) (string, error) {
	// TODO: check for user flag for easy captcha presentation

	if os.Getenv("TERM_PROGRAM") == "iTerm.app" {
		// Use iTerm to show the image if available
		return kc.iTermCaptchaPrompt(captchaPictureURL)
	} else {
		return simpleCaptchaPrompt(captchaPictureURL), nil
	}
}

func (kc *Client) iTermCaptchaPrompt(captchaPictureURL string) (string, error) {
	log.Printf("Detected iTerm, displaying URL: %s\n", captchaPictureURL)
	imgResp, err := kc.client.Get(captchaPictureURL)
	if err != nil {
		return "", errors.Wrap(err, "unable to fetch captcha image")
	}
	var buf bytes.Buffer
	b64Encoder := b64.NewEncoder(b64.StdEncoding, &buf)
	_, _ = io.Copy(b64Encoder, imgResp.Body)
	_ = b64Encoder.Close()

	if os.Getenv("TERM") == "screen" {
		log.Println("Detected tmux, using specific workaround...")
		fmt.Printf("\033Ptmux;\033\033]1337;File=width=40;preserveAspectRatio=1;inline=1;:%s\a\033\\\n", buf.String())
	} else {
		fmt.Printf("\033]1337;File=width=40;preserveAspectRatio=1;inline=1;:%s\a\n", buf.String())
	}
	return prompter.String("Captcha", ""), nil
}

func simpleCaptchaPrompt(captchaPictureURL string) string {
	log.Println("Open this link in a browser:\n", captchaPictureURL)
	return prompter.String("Captcha", "")
}

func (kc *Client) loadFirstPage(loginDetails *creds.LoginDetails) (string, url.Values, error) {
	firstPageURL := loginDetails.URL + "&hl=en&loc=US"

	req, err := http.NewRequest("GET", firstPageURL, nil)
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

	doc.Url, err = url.Parse(firstPageURL)
	if err != nil {
		return "", url.Values{}, errors.Wrap(err, "failed to define URL for html doc")
	}

	authForm, submitURL, err := extractInputsByFormID(doc, "gaia_loginform", "challenge")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build login form data")
	}

	return submitURL, authForm, err
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

	doc.Url, err = url.Parse(submitURL)
	if err != nil {
		return "", url.Values{}, errors.Wrap(err, "failed to define URL for html doc")
	}

	loginForm, loginURL, err := extractInputsByFormID(doc, "gaia_loginform", "challenge")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to build login form data")
	}

	return loginURL, loginForm, err
}

func (kc *Client) loadChallengePage(submitURL string, referer string, authForm url.Values, loginDetails *creds.LoginDetails, preferredChallenges ...string) (*goquery.Document, error) {
	authForm.Set("bgresponse", "js_enabled")

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

	doc.Url, err = url.Parse(submitURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to define URL for html doc")
	}

	errMsg := mustFindErrorMsg(doc)

	if errMsg != "" {
		return nil, errors.New("Invalid username or password")
	}

	const (
		secondFactorHeader   = "This extra step shows it’s really you trying to sign in"
		secondFactorHeader2  = "This extra step shows that it’s really you trying to sign in"
		secondFactorHeader3  = "2-Step Verification"
		secondFactorHeaderJp = "2 段階認証プロセス"
	)

	// have we been asked for 2-Step Verification
	if extractNodeText(doc, "h2", secondFactorHeader) != "" ||
		extractNodeText(doc, "h2", secondFactorHeader2) != "" ||
		extractNodeText(doc, "h1", secondFactorHeader3) != "" ||
		extractNodeText(doc, "h1", secondFactorHeaderJp) != "" {

		responseForm, secondActionURL, err := extractInputsByFormID(doc, "challenge")
		if err != nil {
			return nil, errors.Wrap(err, "unable to extract challenge form")
		}

		logger.Debugf("secondActionURL: %s", secondActionURL)

		// Attempt to select a preferred challenge once
		if len(preferredChallenges) > 0 && !strings.Contains(secondActionURL, fmt.Sprintf("challenge/%s", preferredChallenges[0])) &&
			!strings.Contains(secondActionURL, "challenge/selection") {

			if extractNodeText(doc, "span", "Choose how you want to sign in:") != "" {
				return kc.loadChallengeEntryPage(doc, submitURL, loginDetails, preferredChallenges...)
			}

			if extractNodeText(doc, "button", "Try another way") != "" {
				responseForm.Set("action", "2")
				return kc.loadAlternateChallengePage(secondActionURL, submitURL, responseForm, loginDetails, preferredChallenges...)
			}
		}

		switch {
		case strings.Contains(secondActionURL, "challenge/selection"): // handle selection page

			return kc.loadChallengeEntryPage(doc, submitURL, loginDetails, preferredChallenges...)

		case strings.Contains(secondActionURL, "challenge/totp"): // handle TOTP challenge
			log.Println("Use TOTP challenge.")

			var token = loginDetails.MFAToken
			if token == "" {
				token = prompter.RequestSecurityCode("000000")
			}

			responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/ipp"): // handle SMS challenge
			log.Println("Use SMS challenge.")

			if extractNodeText(doc, "button", "Send text message") != "" {
				responseForm.Set("SendMethod", "SMS") // extractInputsByFormID does not extract the name and value from <button> tag that is the form submit
				doc, err = kc.loadResponsePage(secondActionURL, submitURL, responseForm)
				if err != nil {
					return nil, errors.Wrap(err, "failed to post sms request form")
				}
				doc.Url, err = url.Parse(submitURL)
				if err != nil {
					return nil, errors.Wrap(err, "failed to define URL for html doc")
				}

				submitURL = secondActionURL
				responseForm, secondActionURL, err = extractInputsByFormID(doc, "challenge")
				if err != nil {
					return nil, errors.Wrap(err, "unable to extract challenge form")
				}

				logger.Debugf("After sms request secondActionURL: %s", secondActionURL)
			}

			var token = prompter.StringRequired("Enter SMS token: G-")

			responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/sk"): // handle u2f challenge
			log.Println("Use U2F challenge.")

			facetComponents, err := url.Parse(secondActionURL)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse action URL for U2F challenge")
			}
			facet := facetComponents.Scheme + "://" + facetComponents.Host
			challengeNonce := responseForm.Get("id-challenge")
			appID, data := extractKeyHandles(doc, challengeNonce)
			u2fClient, err := NewU2FClient(challengeNonce, appID, facet, data[0], &U2FDeviceFinder{})
			if err != nil {
				return nil, errors.Wrap(err, "Failed to prompt for second factor.")
			}

			response, err := u2fClient.ChallengeU2F()
			if err != nil {
				logger.WithError(err).Error("Second factor failed.")
				return kc.skipChallengePage(doc, submitURL, secondActionURL, loginDetails)
			}

			responseForm.Set("id-assertion", response)
			responseForm.Set("TrustDevice", "on")

			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/az"): // handle phone challenge
			log.Println("Use phone challenge.")

			dataAttrs := extractDataAttributes(doc, "div[data-context]", []string{"data-context", "data-gapi-url", "data-tx-id", "data-api-key", "data-tx-lifetime"})

			logger.Debugf("prompt with data values: %+v", dataAttrs)

			waitValues := map[string]string{
				"txId": dataAttrs["data-tx-id"],
			}

			log.Println("Open the Google App, and tap 'Yes' on the prompt to sign in")

			_, err := kc.postJSON(fmt.Sprintf("https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key=%s", dataAttrs["data-api-key"]), waitValues, submitURL)
			if err != nil {
				return nil, errors.Wrap(err, "unable to extract post wait tx form")
			}

			// responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/dp"): // handle device push challenge
			log.Println("Use device push challenge.")

			if extraNumber := extractDevicePushExtraNumber(doc); extraNumber != "" {
				log.Println("Check your phone and tap 'Yes' on the prompt, then tap the number:")
				log.Printf("\t%v\n", extraNumber)
				log.Println("Then press ENTER to continue.")
			} else {
				log.Print("Check your phone and tap 'Yes' on the prompt. Then press ENTER to continue.")
			}

			_, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
			if err != nil {
				return nil, errors.Wrap(err, "error reading new line \\n")
			}
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer
			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)

		case strings.Contains(secondActionURL, "challenge/skotp"): // handle one-time HOTP challenge
			log.Println("Use one-time HOTP challenge.")

			log.Println("Get a one-time code by visiting https://g.co/sc on another device where you can use your security key")
			var token = prompter.RequestSecurityCode("000 000")

			responseForm.Set("Pin", token)
			responseForm.Set("TrustDevice", "on") // Don't ask again on this computer

			return kc.loadResponsePage(secondActionURL, submitURL, responseForm)
		}

		return kc.skipChallengePage(doc, submitURL, secondActionURL, loginDetails)

	} else if extractNodeText(doc, "h2", "To sign in to your Google Account, choose a task from the list below.") != "" {
		return kc.loadChallengeEntryPage(doc, submitURL, loginDetails, preferredChallenges...)
	}

	return doc, nil

}

func (kc *Client) skipChallengePage(doc *goquery.Document, submitURL string, secondActionURL string, loginDetails *creds.LoginDetails) (*goquery.Document, error) {

	skipResponseForm, skipActionURL, err := extractInputsByFormQuery(doc, `[action$="skip"]`)
	if err != nil {
		return nil, errors.Wrap(err, "unable to extract skip form")
	}

	if skipActionURL == "" {
		return nil, errors.Errorf("unsupported second factor: %s", secondActionURL)
	}

	return kc.loadAlternateChallengePage(skipActionURL, submitURL, skipResponseForm, loginDetails)
}

func (kc *Client) loadAlternateChallengePage(submitURL string, referer string, authForm url.Values, loginDetails *creds.LoginDetails, preferredChallenges ...string) (*goquery.Document, error) {

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

	doc.Url, err = url.Parse(submitURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to define URL for html doc")
	}

	return kc.loadChallengeEntryPage(doc, submitURL, loginDetails, preferredChallenges...)
}

func (kc *Client) loadChallengeEntryPage(doc *goquery.Document, submitURL string, loginDetails *creds.LoginDetails, preferredChallenges ...string) (*goquery.Document, error) {
	var (
		preference         = len(preferredChallenges)
		preferredSelection *goquery.Selection
	)

	// Search for the most preferred challenge type among available options.
	doc.Find(`form div[data-action="selectchallenge"]`).EachWithBreak(func(i int, s *goquery.Selection) bool {
		challengeType, ok := s.Attr("data-challengetype")
		if !ok {
			return true
		}

		for idx, c := range preferredChallenges {
			if code, ok := challengeTypeToCode[challengeType]; !ok || code != c {
				continue
			}
			if idx < preference {
				preference = idx
				preferredSelection = s
			}
			return true
		}
		return true
	})

	// Extract the challenge ID of the preferred challenge type, if one is found.
	var challengeId string

	if preferredSelection != nil {
		id, ok := preferredSelection.Find(`button[name="challenge"]`).Attr("value")
		if ok {
			challengeId = id
		}
	}

	// Fallback: Select the first available challenge type if no preferred type is found.
	if challengeId == "" {
		challengeSelection := doc.Find(`form div[data-action="selectchallenge"]`).FilterFunction(func(i int, s *goquery.Selection) bool {
			if _, ok := s.Attr("data-challengetype"); !ok {
				return false
			}
			if _, ok := s.Attr("data-challengeid"); !ok {
				return false
			}
			return true
		}).First()

		if challengeSelection != nil {
			challengeId, _ = challengeSelection.Find(`button[name="challenge"]`).Attr("value")
		}
	}

	// If a challenge ID is determined, navigate to the challenge page.
	if challengeId != "" {
		var err error
		doc.Url, err = url.Parse(loginDetails.URL)
		if err != nil {
			return nil, errors.Wrap(err, "error building providerURL")
		}
		responseForm, newActionURL, err := extractInputsByFormQuery(doc, "")
		if err != nil {
			return nil, errors.Wrap(err, "unable to extract challenge form")
		}
		responseForm.Set("challenge", challengeId)
		return kc.loadChallengePage(newActionURL, submitURL, responseForm, loginDetails)
	}

	preference = len(preferredChallenges)
	preferredSelection = nil

	// Search for a challenge entry in form actions, checking for preferred types first.
	doc.Find("form[data-challengeentry]").EachWithBreak(func(i int, s *goquery.Selection) bool {
		action, ok := s.Attr("action")
		if !ok {
			return true
		}

		for idx, c := range preferredChallenges {
			if !strings.Contains(action, fmt.Sprintf("challenge/%s/", c)) {
				continue
			}
			if idx < preference {
				preference = idx
				preferredSelection = s
			}
			return true
		}

		// Fallback for common challenge types if no preference is set.
		if strings.Contains(action, "challenge/totp/") ||
			strings.Contains(action, "challenge/ipp/") ||
			strings.Contains(action, "challenge/az/") ||
			strings.Contains(action, "challenge/skotp/") {

			// Avoid overriding a previously selected preference.
			if preference < 0 {
				preferredSelection = s
			}
		}

		return true
	})

	// Extract the challenge entry from the preferred selection, if available.
	var challengeEntry string
	if preferredSelection != nil {
		if entry, ok := preferredSelection.Attr("data-challengeentry"); ok {
			challengeEntry = entry
		}
	}

	if challengeEntry == "" {
		return nil, errors.New("unable to find supported second factor")
	}

	query := fmt.Sprintf(`[data-challengeentry="%s"]`, challengeEntry)
	responseForm, newActionURL, err := extractInputsByFormQuery(doc, query)
	if err != nil {
		return nil, errors.Wrap(err, "unable to extract challenge form")
	}

	return kc.loadChallengePage(newActionURL, submitURL, responseForm, loginDetails)
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

func extractInputsByFormID(doc *goquery.Document, formID ...string) (url.Values, string, error) {
	// First try to find form by specific id
	for _, id := range formID {
		formData, actionURL, err := extractInputsByFormQuery(doc, fmt.Sprintf("#%s", id))
		if err == nil && actionURL != "" {
			return formData, actionURL, nil
		}
	}

	// If no form found by id or actionURL in the previous forms, search for any form
	formData, actionURL, err := extractInputsByFormQuery(doc, "")
	if err != nil && actionURL != "" {
		return formData, actionURL, errors.New("could not find any forms with actions")
	}

	if len(formData) == 0 {
		return nil, "", errors.New("could not find any forms")
	}

	// Fallback in case no forms with actionURL were found
	return formData, actionURL, err
}

func extractInputsByFormQuery(doc *goquery.Document, formQuery string) (url.Values, string, error) {
	formData := url.Values{}
	var actionAttr string

	query := fmt.Sprintf("form%s", formQuery)

	currentURL := doc.Url.String()

	//get action url
	foundForms := doc.Find(query)
	if len(foundForms.Nodes) == 0 {
		return formData, "", fmt.Errorf("could not find form with query %q", query)
	}

	foundForms.Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionAttr = action
	})

	actionURL, err := generateFullURLIfRelative(actionAttr, currentURL)
	if err != nil {
		return formData, "", errors.Wrap(err, "error getting action URL")
	}

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
			_ = json.Unmarshal(obj, &result) // ignore the error and continue
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

func generateFullURLIfRelative(destination, currentPageURL string) (string, error) {
	if string(destination[0]) == "/" {
		currentURLParsed, err := url.Parse(currentPageURL)
		if err != nil {
			return "", errors.Wrap(err, "error generating full URL")
		}

		return fmt.Sprintf("%s://%s%s", currentURLParsed.Scheme, currentURLParsed.Host, destination), nil
	} else {
		return destination, nil
	}
}

func isKeyHandle(key, challengeTxt string) bool {
	_, err := b64.StdEncoding.DecodeString(key)
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

func extractDevicePushExtraNumber(doc *goquery.Document) string {
	extraNumber := ""
	doc.Find("div[jsname=feLNVc]").Each(func(_ int, s *goquery.Selection) {
		extraNumber = s.Text()
	})
	return extraNumber
}
