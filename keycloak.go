package saml2aws

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"fmt"

	"golang.org/x/net/publicsuffix"
)

// KeyCloakClient wrapper around KeyCloak.
type KeyCloakClient struct {
	client *http.Client
}

// NewKeyCloakClient create a new KeyCloakClient
func NewKeyCloakClient(skipVerify bool) (*KeyCloakClient, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: tr, Jar: jar}

	return &KeyCloakClient{
		client: client,
	}, nil
}

// Authenticate logs into KeyCloak and returns a SAML response
func (kc *KeyCloakClient) Authenticate(loginDetails *LoginDetails) (string, error) {
	var authSubmitURL string
	var samlAssertion string
	authForm := url.Values{}

	samlAssertion = ""

	keyCloakURL := fmt.Sprintf("https://%s", loginDetails.Hostname)

	// fmt.Printf("KeyCloak URL: %s\n\n", keyCloakURL)

	res, err := kc.client.Get(keyCloakURL)
	if err != nil {
		return "", errors.Wrap(err, "error retieving form")
	}

	// fmt.Printf("Response: %d\n\n", res.StatusCode)

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateKeyCloakFormData(authForm, s, loginDetails)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	// log.Printf("id authentication url: %s", authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = kc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving login form")
	}

	// log.Printf("res code = %v status = %s", res.StatusCode, res.Status)

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving body")
	}

	doc, err = goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			log.Fatalf("unable to locate IDP authentication form submit URL")
		}
		if name == "SAMLResponse" {
			val, ok := s.Attr("value")
			if !ok {
				log.Fatalf("unable to locate saml assertion value")
			}
			samlAssertion = val
		}
	})

	return samlAssertion, nil
}

func updateKeyCloakFormData(authForm url.Values, s *goquery.Selection, user *LoginDetails) {
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
