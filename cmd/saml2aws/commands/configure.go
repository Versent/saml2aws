package commands

import (
	"log"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2"
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
	idpAccountPassword := configFlags.Password

	cfgm, err := cfg.NewConfigManager(configFlags.ConfigFile)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(idpAccountName)
	if err != nil {
		return errors.Wrap(err, "failed to load idp account")
	}

	flags.ApplyFlagOverrides(configFlags, account)

	if configFlags.SkipPrompt {
		return saveConfiguration(cfgm, idpAccountName, account, configFlags, idpAccountPassword)
	}

	if err = saml2aws.PromptForConfigurationDetails(account); err != nil {
		return errors.Wrap(err, "failed to input configuration")
	}

	if credentials.SupportsStorage() && idpAccountPassword == "" {
		idpAccountPassword = prompter.Password("Enter password")
		if idpAccountPassword == "" {
			log.Println("No password supplied")
		}
	}

	return saveConfiguration(cfgm, idpAccountName, account, configFlags, idpAccountPassword)
}

func saveConfiguration(cfgm *cfg.ConfigManager, idpAccountName string, account *cfg.IDPAccount, configFlags *flags.CommonFlags, idpAccountPassword string) error {
	if credentials.SupportsStorage() {
		if err := storeCredentials(configFlags, account, idpAccountPassword); err != nil {
			return err
		}
	}

	if err := cfgm.SaveIDPAccount(idpAccountName, account); err != nil {
		return errors.Wrap(err, "failed to save configuration")
	}

	log.Println("")
	log.Println(account)
	log.Println("")
	log.Printf("Configuration saved for IDP account: %s", idpAccountName)

	return nil
}

func storeCredentials(configFlags *flags.CommonFlags, account *cfg.IDPAccount, idpAccountPassword string) error {
	if configFlags.DisableKeychain {
		return nil
	}
	if idpAccountPassword != "" {
		if err := credentials.SaveCredentials(account.URL, account.Username, idpAccountPassword); err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	} else {
		log.Println("No password supplied")
	}
	if account.Provider == onelogin.ProviderName {
		if configFlags.ClientID == "" || configFlags.ClientSecret == "" {
			log.Println("OneLogin provider requires --client-id and --client-secret flags to be set.")
			os.Exit(1)
		}
		if err := credentials.SaveCredentials(path.Join(account.URL, OneLoginOAuthPath), configFlags.ClientID, configFlags.ClientSecret); err != nil {
			return errors.Wrap(err, "error storing client_id and client_secret in keychain")
		}
	}
	return nil
}
