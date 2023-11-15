package browser

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/playwright-community/playwright-go"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "browser")

const DEFAULT_TIMEOUT float64 = 300000

// Client client for browser based Identity Provider
type Client struct {
	BrowserType           string
	BrowserExecutablePath string
	Headless              bool
	// Setup alternative directory to download playwright browsers to
	BrowserDriverDir string
	Timeout          int
}

// New create new browser based client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	return &Client{
		Headless:              idpAccount.Headless,
		BrowserDriverDir:      idpAccount.BrowserDriverDir,
		BrowserType:           strings.ToLower(idpAccount.BrowserType),
		BrowserExecutablePath: idpAccount.BrowserExecutablePath,
		Timeout:               idpAccount.Timeout,
	}, nil
}

// contains checks if a string is present in a slice
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
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

	validBrowserTypes := []string{"chromium", "firefox", "webkit", "chrome", "chrome-beta", "chrome-dev", "chrome-canary", "msedge", "msedge-beta", "msedge-dev", "msedge-canary"}
	if len(cl.BrowserType) > 0 && !contains(validBrowserTypes, cl.BrowserType) {
		return "", fmt.Errorf("invalid browser-type: '%s', only %s are allowed", cl.BrowserType, validBrowserTypes)
	}

	if cl.BrowserType != "" {
		logger.Info(fmt.Sprintf("Setting browser type: %s", cl.BrowserType))
		launchOptions.Channel = playwright.String(cl.BrowserType)
	}

	// Default browser is Chromium as it is widely supported for Identity providers,
	// It can also be set to the other playwright browsers: Firefox and WebKit
	browserType := pw.Chromium
	if cl.BrowserType == "firefox" {
		browserType = pw.Firefox
	} else if cl.BrowserType == "webkit" {
		browserType = pw.WebKit
	}

	// You can set the path to a browser executable to run instead of the playwright-go bundled one. If `executablePath`
	// is a relative path, then it is resolved relative to the current working directory.
	// Note that Playwright only works with the bundled Chromium, Firefox or WebKit, use at your own risk. see:
	if len(cl.BrowserExecutablePath) > 0 {
		logger.Info(fmt.Sprintf("Setting browser executable path: %s", cl.BrowserExecutablePath))
		launchOptions.ExecutablePath = &cl.BrowserExecutablePath
	}

	// currently using the main browsers supported by Playwright: Chromium, Firefox or Webkit
	//
	// this is a sandboxed browser window so password managers and addons are separate
	browser, err := browserType.Launch(launchOptions)
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
	r, _ := page.ExpectRequest(signin_re, nil, client.expectRequestTimeout())
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

func (cl *Client) expectRequestTimeout() playwright.PageExpectRequestOptions {
	timeout := float64(cl.Timeout)
	if timeout < 30000 {
		timeout = DEFAULT_TIMEOUT
	}
	return playwright.PageExpectRequestOptions{Timeout: &timeout}
}
