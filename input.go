package saml2aws

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/segmentio/go-prompt"
)

// LoginDetails used to authenticate to ADFS
type LoginDetails struct {
	Username     string
	Password     string
	Hostname     string
	ProviderName string
}

// PromptForLoginDetails prompt the user to present their username, password and hostname
func PromptForLoginDetails(username, hostname, providerName string) (*LoginDetails, error) {

	fmt.Println("Login for ", username)
	password := prompt.PasswordMasked("Password")

	fmt.Println("")

	return &LoginDetails{
		Username:     strings.TrimSpace(username),
		Password:     strings.TrimSpace(password),
		Hostname:     strings.TrimSpace(hostname),
		ProviderName: strings.TrimSpace(providerName),
	}, nil
}

// PromptForProfileDetails prompt the user to config their username, hostname and provider
func PromptForProfileDetails(username, hostname, providerName string) (*LoginDetails, error) {

	providerName = promptFor("The type of SAML IDP provider (ADFS, ADFS2, Ping, JumpCloud) [%s]", providerName)
	hostname = promptFor("Hostname [%s]", hostname)
	username = promptFor("Username [%s]", username)

	fmt.Println("")

	return &LoginDetails{
		Username:     strings.TrimSpace(username),
		Password:     "",
		Hostname:     strings.TrimSpace(hostname),
		ProviderName: strings.TrimSpace(providerName),
	}, nil
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
	selectedroleindex, _ := reader.ReadString('\n')

	v, err := strconv.Atoi(strings.TrimSpace(selectedroleindex))

	if err != nil {
		return nil, fmt.Errorf("Unrecognised role index")
	}

	if v > len(roles) {
		return nil, fmt.Errorf("You selected an invalid role index")
	}

	return roles[v], nil
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
