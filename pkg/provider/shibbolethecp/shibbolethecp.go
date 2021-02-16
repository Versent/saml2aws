package shibbolethecp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"text/template"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

const SAML_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
const SHIB_DUO_FACTOR = "X-Shibboleth-Duo-Factor"
const SHIB_DUO_PASSCODE = "X-Shibboleth-Duo-Passcode"

// Client wrapper around shibbolethecp enabling authentication and retrieval of assertions
type Client struct {
	provider.ValidateBase

	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

var logger = logrus.WithField("provider", "shibbolethecp")

const authnRequestTpl = `
<S:Envelope 
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
    xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp">
    <S:Body> 
        <saml2p:AuthnRequest
		ID="{{.ID}}" 
		ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
		AssertionConsumerServiceURL="{{.AssertionConsumerServiceURL}}"
		IssueInstant="{{.IssueInstant}}"
		Version="2.0">
			<saml2:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				{{.EntityID}}
			</saml2:Issuer>
		</saml2p:AuthnRequest>       
     </S:Body> 
</S:Envelope>`

type authnRequestData struct {
	ID                          string
	AssertionConsumerServiceURL string
	IssueInstant                string
	EntityID                    string
}

// New creates a new shibboleth-ecp client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr, provider.BuildHttpClientOpts(idpAccount))
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate authenticates to a Shibboleth ECP profile and return the data from the body of the SAML assertion.
func (c *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	// Step 1: Request resource from IdP, indicate we are ECP capable
	ar, err := authnRequest(c.idpAccount.AmazonWebservicesURN)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", loginDetails.URL, ar)
	if err != nil {
		return "", errors.Wrapf(err, "Error creating new http request for %s", loginDetails.URL)
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("charset", "utf-8")
	req.Header.Set(SHIB_DUO_FACTOR, c.idpAccount.MFA)
	req.SetBasicAuth(loginDetails.Username, loginDetails.Password)

	// if user chose passcode, then optionally prompt for the token and set the SHIB_DUO_PASSCODE header
	if c.idpAccount.MFA == "passcode" {
		if loginDetails.MFAToken == "" {
			req.Header.Set(SHIB_DUO_PASSCODE, prompter.RequestSecurityCode("000000"))
		} else {
			req.Header.Set(SHIB_DUO_PASSCODE, loginDetails.MFAToken)
		}
	}

	res, err := c.client.Do(req)
	defer func() {
		_ = res.Body.Close()
	}()

	if err != nil {
		return "", errors.Wrap(err, "Sending initial SOAP authnRequest")
	}

	if res.StatusCode != 200 {
		return "", errors.Wrapf(err, "Response code from IDP at %s: %s", res.Status, res.Request.URL)
	}

	bodyBytes, _ := ioutil.ReadAll(res.Body)
	logger.Debugf("IDP Response: %s", bodyBytes)
	res.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // reset

	// Step 2: Process the returned <AuthnRequest>
	// check for SAML_SUCCESS in S:Body/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value
	assertion, err := extractAssertion(res.Body)
	logger.Debugf("err = %s", err)
	if err != nil {
		return "", err
	}

	logger.Debugf("SAML Assertion: %s", assertion)

	// saml2aws expects the assertion to be base64 encoded
	return base64.StdEncoding.EncodeToString([]byte(assertion)), nil
}

// authnRequest creates a SOAP-XML AuthnRequest from EntityID
func authnRequest(entityID string) (io.Reader, error) {
	// create authnRequest from template, due to fragility in xml/encoding when handling namespaces
	t, err := template.New("authnRequest").Parse(authnRequestTpl)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing authnRequest template")
	}
	ard := authnRequestData{
		ID:                          uuid.New().String(),
		IssueInstant:                time.Now().Format(time.RFC3339),
		AssertionConsumerServiceURL: "https://signin.aws.amazon.com/saml",
		EntityID:                    entityID,
	}

	var buf bytes.Buffer
	bufw := bufio.NewWriter(&buf)
	if err := t.Execute(bufw, ard); err != nil {
		return nil, errors.Wrap(err, "Creating authnRequest from template")
	}
	bufw.Flush()

	// create our http request and set headers
	bufr := bufio.NewReader(&buf)

	return bufr, nil
}

// extractAssertion extracts a SAML assertion from a SOAP response body
func extractAssertion(body io.Reader) (string, error) {
	// parse the response
	doc := etree.NewDocument()
	n, err := doc.ReadFrom(body)
	if err != nil {
		return "", errors.Wrap(err, "Unable to parse IDP response as XML using etree")
	}
	if n <= 0 {
		return "", fmt.Errorf("etree ReadFrom() read %d bytes from IDP response", n)
	}

	// set the root
	root := doc.Root()

	// find status code
	statusCodeElement := root.FindElement("//saml2p:StatusCode")
	if statusCodeElement == nil {
		return "", errors.New("Unable to find StatusCode element by XML path")
	}

	// check statuscode value
	statusCode := statusCodeElement.SelectAttrValue("Value", "unknown")
	logger.Debugf("SAML StatusCode Value = %s", statusCode)
	if statusCode != SAML_SUCCESS {
		return "", errors.Errorf("IDP response did not return success. StatusCode = %s", statusCode)
	}

	// Step 3: Extract the  SOAP-wrapped <Assertion> from IdP
	// find the SAML Response element
	responseElement := root.FindElement("//saml2p:Response")
	if responseElement == nil {
		return "", errors.New("Unable to find Response element in IdP response by XML path")
	}

	// then pull everything from the Response element down into a string to return
	doc.SetRoot(responseElement)
	assertion, err := doc.WriteToString()
	if err != nil {
		return "", errors.Wrap(err, "Could not serialize Response to string")
	}

	return assertion, nil
}
