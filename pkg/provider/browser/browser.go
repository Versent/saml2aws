package browser

import (
	"errors"
	"net/url"

	"github.com/mxschmitt/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

// Client client for browser based Identity Provider
type Client struct {
	persistentDataDir string
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		persistentDataDir: idpAccount.PersistentDataDir,
	}, nil
}

func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	pw, err := playwright.Run(&playwright.RunOptions{
		Browsers: []string{"chromium"},
	})
	if err != nil {
		return "", err
	}

	// currently using Chromium as it is widely supported for Identity providers
	//
	// this is a sandboxed browser window so password managers and addons are separate
	var browser playwright.BrowserContext

	if cl.persistentDataDir != "" {
		// TODO: provide some overrides for this window
		launchOptions := playwright.BrowserTypeLaunchPersistentContextOptions{
			Headless: playwright.Bool(false),
		}

		browser, err = pw.Chromium.LaunchPersistentContext(cl.persistentDataDir, launchOptions)
	} else {
		// TODO: provide some overrides for this window
		launchOptions := playwright.BrowserTypeLaunchOptions{
			Headless: playwright.Bool(false),
		}

		browserNoCtx, err := pw.Chromium.Launch(launchOptions)
		if err != nil {
			return "", err
		}

		browser, err = browserNoCtx.NewContext()
	}

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
