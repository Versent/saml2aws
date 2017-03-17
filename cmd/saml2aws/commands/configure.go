package commands

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
)

// Configure user profile
func Configure(profile string) error {

	config := saml2aws.NewConfigLoader(profile)

	providerName, err := config.LoadProvider()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	username, err := config.LoadUsername()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	hostname, err := config.LoadHostname()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	loginDetails, err := saml2aws.PromptForProfileDetails(username, hostname, providerName)
	if err != nil {
		return errors.Wrap(err, "error accepting password")
	}

	fmt.Println("Saving config:", config.Filename)
	config.SaveUsername(loginDetails.Username)
	config.SaveHostname(loginDetails.Hostname)
	config.SaveProvider(loginDetails.ProviderName)

	return nil
}
