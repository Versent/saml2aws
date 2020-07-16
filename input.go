package saml2aws

import (
	"fmt"
	"log"
	"sort"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
)

// PromptForConfigurationDetails prompt the user to present their hostname, username and mfa
func PromptForConfigurationDetails(idpAccount *cfg.IDPAccount) error {

	providers := MFAsByProvider.Names()

	var err error

	idpAccount.Provider, err = prompter.ChooseWithDefault("Please choose a provider:", idpAccount.Provider, providers)
	if err != nil {
		return errors.Wrap(err, "error selecting provider file")
	}

	mfas := MFAsByProvider.Mfas(idpAccount.Provider)

	// only prompt for MFA if there is more than one option
	if len(mfas) > 1 {
		idpAccount.MFA, err = prompter.ChooseWithDefault("Please choose an MFA", idpAccount.MFA, mfas)
		if err != nil {
			return errors.Wrap(err, "error selecting mfa")
		}

	} else {
		idpAccount.MFA = mfas[0]
	}

	idpAccount.Profile = prompter.String("AWS Profile", idpAccount.Profile)

	idpAccount.URL = prompter.String("URL", idpAccount.URL)
	idpAccount.Username = prompter.String("Username", idpAccount.Username)

	switch idpAccount.Provider {
	case "OneLogin":
		idpAccount.AppID = prompter.String("App ID", idpAccount.AppID)
		log.Println("")
		idpAccount.Subdomain = prompter.String("Subdomain", idpAccount.Subdomain)
		log.Println("")
	case "F5APM":
		idpAccount.ResourceID = prompter.String("Resource ID", idpAccount.ResourceID)
	case "AzureAD":
		idpAccount.AppID = prompter.String("App ID", idpAccount.AppID)
		log.Println("")
	}

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
	if provider == "OneLogin" {
		if loginDetails.ClientID == "" {
			if enteredClientID := prompter.Password("Client ID"); enteredClientID != "" {
				loginDetails.ClientID = enteredClientID
			}
			log.Println("")
		}
		if loginDetails.ClientSecret == "" {
			if enteredCientSecret := prompter.Password("Client Secret"); enteredCientSecret != "" {
				loginDetails.ClientSecret = enteredCientSecret
			}
			log.Println("")
		}
	}

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
