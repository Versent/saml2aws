package commands

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/pkg/cfg"
)

// Configure configure account profiles
func Configure(loginFlags *LoginFlags, cmdline []string) error {

	idpAccountName := loginFlags.IdpAccount

	cfgm, err := cfg.NewConfigManager(cfg.DefaultConfigPath)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(idpAccountName)
	if err != nil {
		return errors.Wrap(err, "failed to load idp account")
	}

	// update username and hostname if supplied
	applyFlagOverrides(loginFlags, account)

	err = saml2aws.PromptForConfigurationDetails(account)
	if err != nil {
		return errors.Wrap(err, "failed to input configuration")
	}

	err = cfgm.SaveIDPAccount(idpAccountName, account)
	if err != nil {
		return errors.Wrap(err, "failed to save configuration")
	}

	fmt.Printf("Configuration saved for IDP account: %s\n", idpAccountName)

	return nil
}
