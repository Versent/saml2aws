package saml2aws

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"golang.org/x/net/publicsuffix"
)

// PingFedClient wrapper around PingFed + PingId enabling authentication and retrieval of assertions
type PingFedClient struct {
	client *http.Client
}

// NewPingFedClient create a new PingFed client
func NewPingFedClient(skipVerify bool) (*PingFedClient, error) {

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
	//disable default behaviour to follow redirects as we use this to detect mfa
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("Redirect")
	}

	return &PingFedClient{
		client: client,
	}, nil
}

// Authenticate Authenticate to PingFed and return the data from the body of the SAML assertion.
func (ac *PingFedClient) Authenticate(loginDetails *LoginDetails) (string, error) {
	var authSubmitURL string
	var samlAssertion string
	mfaRequired := false

	authForm := url.Values{}

	pingFedURL := fmt.Sprintf("https://%s/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices", loginDetails.Hostname)

	res, err := ac.client.Get(pingFedURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateLoginFormData(authForm, s, loginDetails)
	})

	//spew.Dump(authForm)

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

	authSubmitURL = fmt.Sprintf("https://%s%s", loginDetails.Hostname, authSubmitURL)

	//log.Printf("id authentication url: %s", authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = ac.client.Do(req)
	if err != nil {
		//check for redirect, this indicates PingOne MFA being used
		if res.StatusCode == 302 {
			mfaRequired = true
		} else {
			return samlAssertion, errors.Wrap(err, "error retieving login form")
		}
	}

	//process mfa
	if mfaRequired {

		mfaURL, err := res.Location()
		//spew.Dump(mfaURL)

		//follow redirect
		res, err = ac.client.Get(mfaURL.String())
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retieving form")
		}

		//extract form action and jwt token
		form, actionURL, err := extractFormData(res)

		//request mfa auth via PingId (device swipe)
		req, err := http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building mfa authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retieving mfa response")
		}

		//extract form action and csrf token
		form, actionURL, err = extractFormData(res)

		//contine mfa auth with csrf token
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error polling mfa device")
		}

		//extract form action and jwt token
		form, actionURL, err = extractFormData(res)

		//pass PingId auth back to pingfed
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(form.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err = ac.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error authenticating mfa")
		}

	}
	//log.Printf("res code = %v status = %s", res.StatusCode, res.Status)

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

func updateLoginFormData(authForm url.Values, s *goquery.Selection, user *LoginDetails) {
	name, ok := s.Attr("name")
	//	log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "pf.username") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "pf.pass") {
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

func extractFormData(res *http.Response) (url.Values, string, error) {
	formData := url.Values{}
	var actionURL string

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return formData, actionURL, errors.Wrap(err, "failed to build document from response")
	}

	//get action url
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		actionURL = action
	})

	// exxtract form data to passthrough
	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		formData.Add(name, val)
	})

	return formData, actionURL, nil
}
