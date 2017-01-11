package saml2aws

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"

	"github.com/Azure/go-ntlmssp"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

type ADFS2Client struct {
	transport http.RoundTripper
	jar       http.CookieJar
}

func NewADFS2Client(skipVerify bool) (*ADFS2Client, error) {
	transport := &ntlmssp.Negotiator{
		RoundTripper: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		},
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	return &ADFS2Client{
		transport: transport,
		jar:       jar,
	}, nil
}

func (ac *ADFS2Client) Authenticate(loginDetails *LoginDetails) (string, error) {
	var samlAssertion string
	client := http.Client{
		Transport: ac.transport,
		Jar:       ac.jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.SetBasicAuth(loginDetails.Username, loginDetails.Password)
			return nil
		},
	}

	url := fmt.Sprintf("https://%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", loginDetails.Hostname)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return samlAssertion, err
	}
	req.SetBasicAuth(loginDetails.Username, loginDetails.Password)

	res, err := client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving body")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
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
