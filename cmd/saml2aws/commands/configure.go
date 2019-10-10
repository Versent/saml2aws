package commands

import (
	"fmt"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/flags"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider/onelogin"
)

// OneLoginOAuthPath is the path used to generate OAuth token in order to access OneLogin's API.
const OneLoginOAuthPath = "/auth/oauth2/v2/token"

// Configure configure account profiles
func Configure(configFlags *flags.CommonFlags) error {

	idpAccountName := configFlags.IdpAccount

	// pass in alternative location of saml2aws config file, if set.
	cfgm, err := cfg.NewConfigManager(configFlags.ConfigFile)
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
	fmt.Println(account)
	fmt.Println("")
	fmt.Printf("Configuration saved for IDP account: %s\n", idpAccountName)

	return nil
}

func storeCredentials(configFlags *flags.CommonFlags, account *cfg.IDPAccount) error {
	if configFlags.NoKeychain {
		return nil
	}
	if configFlags.Password != "" {
		if err := credentials.SaveCredentials(account.URL, account.Username, configFlags.Password); err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	} else {
		password := prompter.Password("Password")
		if password != "" {
			if confirmPassword := prompter.Password("Confirm"); confirmPassword == password {
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
	if account.Provider == onelogin.ProviderName {
		if configFlags.ClientID == "" || configFlags.ClientSecret == "" {
			fmt.Println("OneLogin provider requires --client_id and --client_secret flags to be set.")
			os.Exit(1)
		}
		if err := credentials.SaveCredentials(path.Join(account.URL, OneLoginOAuthPath), configFlags.ClientID, configFlags.ClientSecret); err != nil {
			return errors.Wrap(err, "error storing client_id and client_secret in keychain")
		}
	}
	return nil
}
