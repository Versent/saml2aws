package commands

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	prompt "github.com/segmentio/go-prompt"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/flags"
)

// Configure configure account profiles
func Configure(configFlags *flags.CommonFlags) error {

	idpAccountName := configFlags.IdpAccount

	cfgm, err := cfg.NewConfigManager(cfg.DefaultConfigPath)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(idpAccountName)
	if err != nil {
		return errors.Wrap(err, "failed to load idp account")
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(configFlags, account)

	// do we need to prompt for values now?
	if !configFlags.SkipPrompt {
		err = saml2aws.PromptForConfigurationDetails(account)
		if err != nil {
			return errors.Wrap(err, "failed to input configuration")
		}

		if credentials.SupportsStorage() {
			if err := storeCredentials(configFlags, account); err != nil {
				return err
			}
		}
	}

	err = cfgm.SaveIDPAccount(idpAccountName, account)
	if err != nil {
		return errors.Wrap(err, "failed to save configuration")
	}

	fmt.Println("")
	fmt.Printf("Configuration saved for IDP account: %s\n", idpAccountName)

	return nil
}

func storeCredentials(configFlags *flags.CommonFlags, account *cfg.IDPAccount) error {
	if configFlags.Password != "" {
		if err := credentials.SaveCredentials(account.URL, account.Username, configFlags.Password); err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	} else {
		password := prompt.PasswordMasked("Password")
		if password != "" {
			if confirmPassword := prompt.PasswordMasked("Confirm"); confirmPassword == password {
				if err := credentials.SaveCredentials(account.URL, account.Username, password); err != nil {
					return errors.Wrap(err, "error storing password in keychain")
				}
			} else {
				fmt.Println("Passwords did not match")
				os.Exit(1)
			}
		} else {
			fmt.Println("No password supplied")
		}
	}
	return nil
}
