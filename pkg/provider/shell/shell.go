package shell

import (
	"errors"
	os "os"
	"os/exec"

	"github.com/sirupsen/logrus"

	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

var logger = logrus.WithField("provider", "shell")

// Client is a wrapper representing an External SAML client
type Client struct {
}

// New creates a new external client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {
	c := &Client{}
	return c, nil
}

// Authenticate executes the URL as a local command, excepting a base64-encoded SAML Assertion
func (oc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {
	logger.Infof("Executing %s", loginDetails.URL)
	cmd := exec.Command("sh", "-c", loginDetails.URL)
	samlResponse, err := cmd.Output()
	return string(samlResponse), err
}

func (oc *Client) Validate(ld *creds.LoginDetails) error {
	if ld.URL == "" {
		return errors.New("Empty URL")
	}

	const executableBits = 0o111
	if stat, err := os.Stat(ld.URL); os.IsNotExist(err) || ((stat.Mode() & executableBits) == 0) {
		return errors.New("URL for shell provider does not point to a valid executable")
	}

	return nil
}
