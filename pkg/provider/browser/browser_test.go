package browser

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var response = `
	<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
		<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
			<samlp:Status>
				<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
			</samlp:Status>
			<saml:EncryptedAssertion>
				<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>hKoNWraWb2YHo6B8ZFI5wOj8C0zdeYnQpaIE14vqe67LCy9e4Y+q7lMTRa7gNa6WZMJbkj1aQ/omsQLRVMkknKFoGD244J0Or9Ma8aXoEkQuRFyw90G4SkH5KuE6ZjUMJkMZN6xDYC+CozYiD6Pfchth/Ks64dNLJ2REau1dV/0=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
					<xenc:CipherData>
						<xenc:CipherValue>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</xenc:CipherValue>
					</xenc:CipherData>
				</xenc:EncryptedData>
			</saml:EncryptedAssertion>
	</samlp:Response>
`

func TestValidate(t *testing.T) {
	currentSAMLResponse := getSAMLResponse
	defer func() {
		getSAMLResponse = currentSAMLResponse
	}()
	getSAMLResponse = fakeSAMLResponse
	account := &cfg.IDPAccount{
		Headless: true,
	}
	client, err := New(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{
		URL:             "https://google.com/",
		DownloadBrowser: true,
	}
	resp, err := client.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, resp, response)
}

func TestInvalidBrowserType(t *testing.T) {
	currentSAMLResponse := getSAMLResponse
	defer func() {
		getSAMLResponse = currentSAMLResponse
	}()
	getSAMLResponse = fakeSAMLResponse
	account := &cfg.IDPAccount{
		BrowserType: "invalid",
	}
	client, err := New(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{
		URL:             "https://google.com/",
		DownloadBrowser: true,
	}
	_, err = client.Authenticate(loginDetails)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid browser-type: 'invalid', only [chromium firefox webkit chrome chrome-beta chrome-dev chrome-canary msedge msedge-beta msedge-dev msedge-canary] are allowed")
}

func TestInvalidBrowserExecutablePath(t *testing.T) {
	currentSAMLResponse := getSAMLResponse
	defer func() {
		getSAMLResponse = currentSAMLResponse
	}()
	getSAMLResponse = fakeSAMLResponse
	account := &cfg.IDPAccount{
		BrowserExecutablePath: "FAKEPATH",
	}
	client, err := New(account)
	assert.Nil(t, err)
	loginDetails := &creds.LoginDetails{
		URL: "https://google.com/",
	}
	_, err = client.Authenticate(loginDetails)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Failed to launch chromium because executable doesn't exist at FAKEPATH")
}

// Test that if download directory does not have browsers, it fails with expected error message
func TestNoBrowserDriverFail(t *testing.T) {
	account := &cfg.IDPAccount{
		Headless:         true,
		BrowserDriverDir: t.TempDir(), // set up a directory we know won't have drivers
	}
	loginDetails := &creds.LoginDetails{
		URL: "https://google.com/",
	}
	client, _ := New(account)
	_, err := client.Authenticate(loginDetails)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "please install the driver")
}

func fakeSAMLResponse(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	return response, nil
}

func TestSigninRegex1(t *testing.T) {
	regex, err := signinRegex()
	assert.Nil(t, err)
	match := regex.MatchString("https://signin.aws.amazon.com/saml")
	assert.True(t, match)
}

func TestSigninRegexFail(t *testing.T) {
	regex, err := signinRegex()
	assert.Nil(t, err)
	match := regex.MatchString("https://google.com/")
	assert.False(t, match)
}

func TestGetSAMLResponse(t *testing.T) {
	samlp := `
	<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
		<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
			<samlp:Status>
				<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
			</samlp:Status>
			<saml:EncryptedAssertion>
				<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>hKoNWraWb2YHo6B8ZFI5wOj8C0zdeYnQpaIE14vqe67LCy9e4Y+q7lMTRa7gNa6WZMJbkj1aQ/omsQLRVMkknKFoGD244J0Or9Ma8aXoEkQuRFyw90G4SkH5KuE6ZjUMJkMZN6xDYC+CozYiD6Pfchth/Ks64dNLJ2REau1dV/0=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo>
					<xenc:CipherData>
						<xenc:CipherValue>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</xenc:CipherValue>
					</xenc:CipherData>
				</xenc:EncryptedData>
			</saml:EncryptedAssertion>
	</samlp:Response>
`

	idpAccount := cfg.IDPAccount{
		Headless: true,
		Timeout:  100000,
	}

	client, err := New(&idpAccount)
	assert.Nil(t, err)
	params := url.Values{}
	params.Add("foo1", "bar1")
	params.Add("SAMLResponse", samlp)
	params.Add("foo2", "bar2")
	url := "https://google.com/"
	page := &mocks.Page{}
	resp := &mocks.Response{}
	req := &mocks.Request{}
	regex, err := signinRegex()
	assert.Nil(t, err)
	page.Mock.On("Goto", url).Return(resp, nil)
	page.Mock.On("ExpectRequest", regex, client.expectRequestTimeout()).Return(req)
	req.Mock.On("PostData").Return(params.Encode(), nil)
	// loginDetails := &creds.LoginDetails{
	//	URL: url,
	//}
	// samlResp, err := getSAMLResponse(page, loginDetails, client)
	// assert.Nil(t, err)
	// assert.Equal(t, samlp, samlResp)
}

func TestExpectRequestOptions(t *testing.T) {
	timeout := float64(100000)
	idpAccount := cfg.IDPAccount{
		Headless: true,
		Timeout:  int(timeout),
	}

	client, err := New(&idpAccount)
	assert.Nil(t, err)

	options := client.expectRequestTimeout()
	if *options.Timeout != timeout {
		t.Errorf("Unexpected value for timeout [%.0f]: expected [%.0f]", *options.Timeout, timeout)
	}
}

func TestExpectRequestOptionsDefaultTimeout(t *testing.T) {
	idpAccount := cfg.IDPAccount{
		Headless: true,
		Timeout:  1000,
	}

	client, err := New(&idpAccount)

	if err != nil {
		t.Errorf("Unable to create browser")
	}

	options := client.expectRequestTimeout()
	if *options.Timeout != DEFAULT_TIMEOUT {
		t.Errorf("Unexpected value for timeout [%.0f]: expected [%.0f]", *options.Timeout, DEFAULT_TIMEOUT)
	}
}

func TestAutoFill(t *testing.T) {
	// 3 different login pages
	pageLocations := []string{
		"example/loginpage.html",
		"example/loginpage-button-submit.html",
		"example/loginpage-without-submit.html",
	}
	// iterate over each login page
	for _, pageLocation := range pageLocations {
		data, err := os.ReadFile(pageLocation)
		require.Nil(t, err)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(data)
		}))
		defer ts.Close()

		pw, _ := playwright.Run()
		browser, _ := pw.Chromium.Launch()
		context, _ := browser.NewContext()
		page, _ := context.NewPage()
		_, _ = page.Goto(ts.URL)

		loginDetails := &creds.LoginDetails{URL: ts.URL, Username: "golang", Password: "gopher"}
		_ = autoFill(page, loginDetails)

		username, _ := page.Locator("input[name='username']").First().InputValue()
		assert.Equal(t, "golang", username)
		password, _ := page.Locator("input[type='password']").First().InputValue()
		assert.Equal(t, "gopher", password)

		result, _ := page.Locator("div#result").Evaluate("el => el.innerText", nil)
		assert.Equal(t, "golang:gopher", result)
	}
}
