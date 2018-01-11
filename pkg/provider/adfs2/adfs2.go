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
	idpAccount *cfg.IDPAccount
	transport  http.RoundTripper
	jar        http.CookieJar
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

	return &Client{
		transport:  transport,
		idpAccount: idpAccount,
		jar:        jar,
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

	url := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)
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
	//if Authmethod is SecurID authentication then need to enter securid passcode
	if strings.Contains(Authmethod, "SecurIDAuthentication") {
		token := prompt.StringRequired("Enter passcode")

		//build request
		otpReq := url.Values{}
		otpReq.Add("otp", token)
		otpReq.Add("message", "")

		//submit otp
		req, err = http.NewRequest("POST", actionURL, strings.NewReader(otpReq.Encode()))
		if err != nil {
			return "", errors.Wrap(err, "error building authentication request")
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		logger.WithField("actionURL", actionURL).WithField("req", dump.RequestString(req)).Debug("POST")

		res, err = ac.client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "error polling mfa device")
		}

		logger.WithField("actionURL", actionURL).WithField("res", dump.ResponseString(res)).Debug("POST")

		//extract form action and jwt token
		form, actionURL, err = extractFormData(res)
		if err != nil {
			return "", errors.Wrap(err, "error extracting mfa form data")
		}

	}


	//check for second redirect where RSA expects the TOTP text message

	if res.StatusCode ==302 {
		ac.mfaRequired = true
	}



	//For entering POST the direct
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return samlAssertion, err
	}

	//if request data



)
	return samlAssertion, nil
}
