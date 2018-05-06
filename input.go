package saml2aws

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
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
			return errors.Wrap(err, "error selecting provider file")
		}

	} else {
		idpAccount.MFA = mfas[0]
	}

	fmt.Println("")

	idpAccount.URL = prompter.String("URL", idpAccount.URL)
	idpAccount.Username = prompter.String("Username", idpAccount.Username)

	fmt.Println("")

	return nil
}

// PromptForLoginDetails prompt the user to present their username, password
func PromptForLoginDetails(loginDetails *creds.LoginDetails) error {

	fmt.Println("To use saved password just hit enter.")

	loginDetails.Username = prompter.String("Username", loginDetails.Username)

	if enteredPassword := prompter.Password("Password"); enteredPassword != "" {
		loginDetails.Password = enteredPassword
	}

	fmt.Println("")

	return nil
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func PromptForAWSRoleSelection(accounts []*AWSAccount) (*AWSRole, error) {

	roles := map[string]*AWSRole{}

	for _, account := range accounts {
		for _, role := range account.Roles {
			// name := fmt.Sprintf("%s / %s", role.Name, strings.TrimPrefix(account.Name, "Account: "))
			name := fmt.Sprintf("%s / %s", role.Name, account.Name)
			roles[name] = role
		}
	}

	roleOptions := []string{}

	for k := range roles {
		roleOptions = append(roleOptions, k)
	}

	selectedRole, err := prompter.ChooseWithDefault("Please choose the role", "", roleOptions)
	if err != nil {
		return nil, errors.Wrap(err, "Role selection failed")
	}

	return roles[selectedRole], nil
}
