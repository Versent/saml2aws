package jumpcloud

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

const (
	jcSSOBaseURL  = "https://sso.jumpcloud.com/"
	xsrfURL       = "https://console.jumpcloud.com/userconsole/xsrf"
	authSubmitURL = "https://console.jumpcloud.com/userconsole/auth"
)

// Client is a wrapper representing a JumpCloud SAML client
type Client struct {
	client *provider.HTTPClient
}

// XSRF is for unmarshalling the xsrf token in the response
type XSRF struct {
	Token string `json:"xsrf"`
}

// AuthRequest is to be sent to JumpCloud as the auth req body
type AuthRequest struct {
	Context    string
	RedirectTo string
	Email      string
	Password   string
	OTP        string
}

// JCRedirect is for unmarshalling the redirect address from the response after the auth
type JCRedirect struct {
	Address string `json:"redirectTo"`
}

type JCMessage struct {
	Message string `json:"message"`
}

// New creates a new JumpCloud client
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

// Authenticate logs into JumpCloud and returns a SAML response
func (jc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	var samlAssertion string
	var a AuthRequest
	re := regexp.MustCompile(jcSSOBaseURL)

	// Start by getting the XSRF Token
	res, err := jc.client.Get(xsrfURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving XSRF Token")
	}

	// Grab the web response that has the xsrf in it
	xsrfBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error reading body of XSRF response")
	}

	// Unmarshall the answer and store the token
	var x = new(XSRF)
	err = json.Unmarshal(xsrfBody, &x)
	if err != nil {
		log.Fatalf("Error unmarshalling xsrf response! %v", err)
	}

	// Populate our Auth body for the POST
	a.Context = "sso"
	a.RedirectTo = re.ReplaceAllString(loginDetails.URL, "")
	a.Email = loginDetails.Username
	a.Password = loginDetails.Password

	authBody, err := json.Marshal(a)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build auth request body")
	}

	// Generate our auth request
	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(string(authBody)))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	// Add the necessary headers to the auth request
	req.Header.Add("X-Xsrftoken", x.Token)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	res, err = jc.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login form")
	}

	// Check if we get a 401.  If we did, and MFA is required, get the OTP and resubmit.
	// Otherwise log the authentication message as a fatal error.
	if res.StatusCode == 401 {

		// Grab the body from the response that has the message in it.
		messageBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "Error reading body")
		}

		// Unmarshall the body to get the message.
		var jcmsg = new(JCMessage)
		err = json.Unmarshal(messageBody, &jcmsg)
		if err != nil {
			log.Fatalf("Error unmarshalling message response! %v", err)
		}

		// If the error indicates something other than missing MFA, then it's fatal.
		if jcmsg.Message != "MFA required." {
			errMsg := fmt.Sprintf("Jumpcloud error: %s", jcmsg.Message)
			return samlAssertion, errors.Wrap(err, errMsg)
		}

		// Get the user's MFA token and re-build the body
		a.OTP = loginDetails.MFAToken
		if a.OTP == "" {
			a.OTP = prompter.StringRequired("MFA Token")
		}

		authBody, err = json.Marshal(a)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building authentication req body after getting MFA Token")
		}

		// Re-request with our OTP
		req, err = http.NewRequest("POST", authSubmitURL, strings.NewReader(string(authBody)))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error building MFA authentication request")
		}

		// Re-add the necessary headers to our remade auth request
		req.Header.Add("X-Xsrftoken", x.Token)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")

		// Resubmit
		res, err = jc.client.Do(req)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error submitting MFA login form")
		}
	}

	// Check if our auth was successful
	if res.StatusCode == 200 {
		// Grab the body from the response that has the redirect in it.
		reDirBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "Error reading body")
		}

		// Unmarshall the body to get the redirect address
		var jcrd = new(JCRedirect)
		err = json.Unmarshal(reDirBody, &jcrd)
		if err != nil {
			log.Fatalf("Error unmarshalling redirectTo response! %v", err)
		}

		// Send the final GET for our SAML response
		res, err = jc.client.Get(jcrd.Address)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error submitting request for SAML value")
		}

		//try to extract SAMLResponse
		doc, err := goquery.NewDocumentFromReader(res.Body)
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

	} else {
		errMsg := fmt.Sprintf("error when trying to auth, status code %d", res.StatusCode)
		return samlAssertion, errors.Wrap(err, errMsg)
	}

	return samlAssertion, nil
}
