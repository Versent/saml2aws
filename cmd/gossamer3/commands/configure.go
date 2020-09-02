package commands

import (
	"log"
	"os"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/GESkunkworks/gossamer3/pkg/prompter"
	"github.com/pkg/errors"
)

// Configure configure account profiles
func Configure(configFlags *flags.CommonFlags) error {

	idpAccountName := configFlags.IdpAccount

	// pass in alternative location of g3 config file, if set.
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
		err = g3.PromptForConfigurationDetails(account)
		if err != nil {
			return errors.Wrap(err, "failed to input configuration")
		}

		if credentials.SupportsStorage() {
			if err := storeCredentials(configFlags, account); err != nil {
				return err
			}
		}
	}

	err = cfgm.SaveIDPAccount(account)
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
	password := prompter.Password("Password")
	if password != "" {
		if confirmPassword := prompter.Password("Confirm"); confirmPassword == password {
			if err := credentials.SaveCredentials(account.URL, account.Username, password); err != nil {
				return errors.Wrap(err, "error storing password in keychain")
			}
		} else {
			log.Println("Passwords did not match")
			os.Exit(1)
		}
	} else {
		log.Println("No password supplied")
	}
	return nil
}
