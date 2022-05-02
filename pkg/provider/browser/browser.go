package browser

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/mxschmitt/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

// Client client for browser based Identity Provider
type Client struct {
	idpAccount *cfg.IDPAccount
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{idpAccount: idpAccount}, nil
}

func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	pw, err := playwright.Run()
	if err != nil {
		return "", err
	}

	// TODO: provide some overrides for this window
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(false),
	}

	if cl.idpAccount.BrowserType != "" {
		logger.Info(fmt.Sprintf("Setting browser type: %s", cl.idpAccount.BrowserType))
		launchOptions.Channel = playwright.String(cl.idpAccount.BrowserType)
	}

	// currently using Chromium as it is widely supported for Identity providers
	//
	// this is a sandboxed browser window so password managers and addons are separate
	browser, err := pw.Chromium.Launch(launchOptions)
	if err != nil {
		return "", err
	}

	page, err := browser.NewPage()
	if err != nil {
		return "", err
	}

	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	r := page.WaitForRequest("https://signin.aws.amazon.com/saml")
	data, err := r.PostData()
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	logger.Info("clean up browser")

	if err = browser.Close(); err != nil {
		return "", err
	}
	if err = pw.Stop(); err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {

	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}

	return nil
}
