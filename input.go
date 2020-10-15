package gossamer3

import (
	"fmt"
	"log"
	"sort"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/prompter"
	"github.com/pkg/errors"
)

// PromptForConfigurationDetails prompt the user to present their hostname, username and mfa
func PromptForConfigurationDetails(idpAccount *cfg.IDPAccount) error {

	providers := MFAsByProvider.Names()

	var err error

	idpAccount.Name = prompter.String("Config name", idpAccount.Name)

	idpAccount.Provider, err = prompter.ChooseWithDefault("Please choose a provider:", providers[0], providers)
	if err != nil {
		return errors.Wrap(err, "error selecting provider file")
	}

	mfas := MFAsByProvider.Mfas(idpAccount.Provider)

	// only prompt for MFA if there is more than one option
	if len(mfas) > 1 {
		idpAccount.MFA, err = prompter.ChooseWithDefault("Please choose an MFA:", mfas[0], mfas)
		if err != nil {
			return errors.Wrap(err, "error selecting mfa")
		}

	} else {
		idpAccount.MFA = mfas[0]
	}

	idpAccount.Profile = prompter.String("AWS Profile", idpAccount.Profile)

	idpAccount.URL = prompter.String("URL", idpAccount.URL)
	idpAccount.AmazonWebservicesURN = prompter.String("AWS URN", idpAccount.AmazonWebservicesURN)
	idpAccount.Username = prompter.String("Username", idpAccount.Username)

	return nil
}

// PromptForLoginDetails prompt the user to present their username, password
func PromptForLoginDetails(loginDetails *creds.LoginDetails, provider string) error {

	log.Println("To use saved password just hit enter.")

	loginDetails.Username = prompter.String("Username", loginDetails.Username)

	if enteredPassword := prompter.Password("Password"); enteredPassword != "" {
		loginDetails.Password = enteredPassword
	}
	log.Println("")

	return nil
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func PromptForAWSRoleSelection(accounts []*AWSAccount) (*AWSRole, error) {

	roles := map[string]*AWSRole{}
	var roleOptions []string

	for _, account := range accounts {
		for _, role := range account.Roles {
			name := fmt.Sprintf("%s / %s", account.Name, role.Name)
			roles[name] = role
			roleOptions = append(roleOptions, name)
		}
	}

	sort.Strings(roleOptions)

	selectedRole, err := prompter.ChooseWithDefault("Please choose the role", roleOptions[0], roleOptions)
	if err != nil {
		return nil, errors.Wrap(err, "Role selection failed")
	}

	return roles[selectedRole], nil
}
