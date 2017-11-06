package adfs2

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
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
)

// Client client for adfs2
type Client struct {
	transport http.RoundTripper
	jar       http.CookieJar
}

// New new adfs2 client with ntlmssp configured
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	transport := &ntlmssp.Negotiator{
		RoundTripper: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
		},
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		transport: transport,
		jar:       jar,
	}, nil
}

// Authenticate authenticate the user using the supplied login details
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	var samlAssertion string
	client := http.Client{
		Transport: ac.transport,
		Jar:       ac.jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.SetBasicAuth(loginDetails.Username, loginDetails.Password)
			return nil
		},
	}

	url := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", loginDetails.URL)
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
