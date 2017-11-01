package saml2aws

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/segmentio/go-prompt"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
)

// PromptForConfigurationDetails prompt the user to present their hostname, username and mfa
func PromptForConfigurationDetails(idpAccount *cfg.IDPAccount) error {

	providers := MFAsByProvider.Names()

	var err error

	idpAccount.Provider, err = promptForSelection("\nPlease choose the provider you would like to use:\n", providers)
	if err != nil {
		return errors.Wrap(err, "error selecting provider file")
	}

	mfas := MFAsByProvider.Mfas(idpAccount.Provider)

	idpAccount.MFA, err = promptForSelection("\nPlease choose an MFA you would like to use:\n", mfas)
	if err != nil {
		return errors.Wrap(err, "error selecting provider file")
	}

	fmt.Println("")

	idpAccount.URL = promptForURL("URL [%s]", idpAccount.URL)
	idpAccount.Username = promptFor("Username [%s]", idpAccount.Username)

	fmt.Println("")

	return nil
}

// PromptForLoginDetails prompt the user to present their username, password and hostname
func PromptForLoginDetails(loginDetails *creds.LoginDetails) error {

	//	loginDetails.Hostname = promptFor("Hostname [%s]", loginDetails.Hostname)

	fmt.Println("To use saved password just hit enter.")

	loginDetails.Username = promptFor("Username [%s]", loginDetails.Username)

	if enteredPassword := prompt.PasswordMasked("Password"); enteredPassword != "" {
		loginDetails.Password = enteredPassword
	}

	fmt.Println("")

	return nil
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func PromptForAWSRoleSelection(accounts []*AWSAccount) (*AWSRole, error) {

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Please choose the role you would like to assume: ")

	roles := []*AWSRole{}

	for _, account := range accounts {
		fmt.Println(account.Name)
		for _, role := range account.Roles {
			fmt.Println("[", len(roles), "]: ", role.Name)
			fmt.Println()
			roles = append(roles, role)
		}
	}

	fmt.Print("Selection: ")
	selectedRoleIndex, _ := reader.ReadString('\n')

	v, err := strconv.Atoi(strings.TrimSpace(selectedRoleIndex))

	if err != nil {
		return nil, fmt.Errorf("Unrecognised role index")
	}

	if v > len(roles) {
		return nil, fmt.Errorf("You selected an invalid role index")
	}

	return roles[v], nil
}

func promptForSelection(prompt string, options []string) (string, error) {

	reader := bufio.NewReader(os.Stdin)

	fmt.Println(prompt)

	for i, val := range options {
		fmt.Println("[", i, "]: ", val)
		fmt.Println()
	}

	var v int
	var err error

	for {
		fmt.Print("Selection: ")
		selectedRoleIndex, _ := reader.ReadString('\n')

		v, err = strconv.Atoi(strings.TrimSpace(selectedRoleIndex))
		if err != nil {
			continue
		}

		if v >= 0 && v < len(options) {
			break
		}

		fmt.Println("Invalid selection")
	}

	return options[v], nil
}

func promptFor(promptString, defaultValue string) string {
	var val string

	// do while
	for ok := true; ok; ok = strings.TrimSpace(defaultValue) == "" && strings.TrimSpace(val) == "" {
		val = prompt.String(promptString, defaultValue)
	}

	if val == "" {
		val = defaultValue
	}

	return val
}

func promptForURL(promptString, defaultValue string) string {
	var rawURL string

	// do while
	for {
		rawURL = prompt.String(promptString, defaultValue)

		if rawURL == "" {
			rawURL = defaultValue
		}

		_, err := url.ParseRequestURI(rawURL)
		if err != nil {
			fmt.Println("please enter a valid url eg https://id.example.com")
		} else {
			break
		}
	}

	return rawURL
}
