package browser

import (
	"errors"
	"net/url"
	"regexp"

	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

const DEFAULT_TIMEOUT float64 = 300000

// Client client for browser based Identity Provider
type Client struct {
	Headless bool
	// Setup alternative directory to download playwright browsers to
	BrowserDriverDir string
	Timeout          int
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		Headless:         idpAccount.Headless,
		BrowserDriverDir: idpAccount.BrowserDriverDir,
		Timeout:          idpAccount.Timeout,
	}, nil
}

func (cl *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	runOptions := playwright.RunOptions{}
	if cl.BrowserDriverDir != "" {
		runOptions.DriverDirectory = cl.BrowserDriverDir
	}

	// Optionally download browser drivers if specified
	if loginDetails.DownloadBrowser {
		err := playwright.Install(&runOptions)
		if err != nil {
			return "", err
		}
	}

	pw, err := playwright.Run(&runOptions)
	if err != nil {
		return "", err
	}

	// TODO: provide some overrides for this window
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(cl.Headless),
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

	defer func() {
		logger.Info("clean up browser")
		if err := browser.Close(); err != nil {
			logger.Info("Error when closing browser", err)
		}
		if err := pw.Stop(); err != nil {
			logger.Info("Error when stopping pm", err)
		}
	}()

	return getSAMLResponse(page, loginDetails, cl)
}

var getSAMLResponse = func(page playwright.Page, loginDetails *creds.LoginDetails, client *Client) (string, error) {
	logger.WithField("URL", loginDetails.URL).Info("opening browser")

	if _, err := page.Goto(loginDetails.URL); err != nil {
		return "", err
	}

	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	signin_re, err := signinRegex()
	if err != nil {
		return "", err
	}

	logger.Info("waiting ...")
	r, _ := page.WaitForRequest(signin_re, client.waitForRequestTimeout())
	data, err := r.PostData()
	if err != nil {
		return "", err
	}

	values, err := url.ParseQuery(data)
	if err != nil {
		return "", err
	}

	return values.Get("SAMLResponse"), nil
}

func signinRegex() (*regexp.Regexp, error) {
	// https://docs.aws.amazon.com/general/latest/gr/signin-service.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Ningxia.html
	// https://docs.amazonaws.cn/en_us/aws/latest/userguide/endpoints-Beijing.html
	return regexp.Compile(`https:\/\/((.*\.)?signin\.(aws\.amazon\.com|amazonaws-us-gov\.com|amazonaws\.cn))\/saml`)
}

func (cl *Client) Validate(loginDetails *creds.LoginDetails) error {

	if loginDetails.URL == "" {
		return errors.New("empty URL")
	}

	return nil
}

func (cl *Client) waitForRequestTimeout() playwright.PageWaitForRequestOptions {
	timeout := float64(cl.Timeout)
	if timeout < 30000 {
		timeout = DEFAULT_TIMEOUT
	}
	return playwright.PageWaitForRequestOptions{Timeout: &timeout}
}
