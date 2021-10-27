package adfs2

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/cookiejar"

	"github.com/versent/saml2aws/v2/pkg/provider"

	"golang.org/x/net/publicsuffix"

	"github.com/Azure/go-ntlmssp"
	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "adfs2")

// Client client for adfs2
type Client struct {
	provider.ValidateBase

	idpAccount *cfg.IDPAccount
	client     *http.Client
}

// New new adfs2 client with ntlmssp configured
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	transport := &ntlmssp.Negotiator{
		RoundTripper: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
		},
	}

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate authenticate the user using the supplied login details
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	switch ac.idpAccount.MFA {
	case "RSA":
		return ac.authenticateRsa(loginDetails)
	default:
		return ac.authenticateNTLM(loginDetails) // this is chosen as the default to maintain compatibility with existing users
	}
}

func extractSamlAssertion(doc *goquery.Document) (string, error) {
	var samlAssertion string

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
