package commands

import (
	"log"
	"os"
	"path"

	"github.com/pkg/errors"
	saml2aws "github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider/onelogin"
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

	log.Println("")
	log.Println(account)
	log.Println("")
	log.Printf("Configuration saved for IDP account: %s", idpAccountName)

	return nil
}

func storeCredentials(configFlags *flags.CommonFlags, account *cfg.IDPAccount) error {
	if configFlags.DisableKeychain {
		return nil
	}
	if configFlags.Password != "" {
		if err := credentials.SaveCredentials(account.Name, account.URL, account.Username, configFlags.Password); err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	} else {
		password := prompter.Password("Password")
		if password != "" {
			if confirmPassword := prompter.Password("Confirm"); confirmPassword == password {
				if err := credentials.SaveCredentials(account.Name, account.URL, account.Username, password); err != nil {
					return errors.Wrap(err, "error storing password in keychain")
				}
			} else {
				log.Println("Passwords did not match")
				os.Exit(1)
			}
		} else {
			log.Println("No password supplied")
		}
	}
	if account.Provider == onelogin.ProviderName {
		if configFlags.ClientID == "" || configFlags.ClientSecret == "" {
			log.Println("OneLogin provider requires --client-id and --client-secret flags to be set.")
			os.Exit(1)
		}
		// we store the OneLogin token in a different secret (idpName + the one login suffix)
		if err := credentials.SaveCredentials(account.Name+credentials.OneLoginTokenSuffix, path.Join(account.URL, OneLoginOAuthPath), configFlags.ClientID, configFlags.ClientSecret); err != nil {
			return errors.Wrap(err, "error storing client_id and client_secret in keychain")
		}
	}
	return nil
}
