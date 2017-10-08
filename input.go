package saml2aws

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/segmentio/go-prompt"
)

// LoginDetails used to authenticate to ADFS
type LoginDetails struct {
	Username string
	Password string
	Hostname string
}

// Validate validate the login details
func (ld *LoginDetails) Validate() error {
	if ld.Hostname == "" {
		return errors.New("Missing hostname")
	}
	if ld.Username == "" {
		return errors.New("Missing username")
	}
	if ld.Password == "" {
		return errors.New("Missing password")
	}
	return nil
}

// PromptForLoginDetails prompt the user to present their username, password and hostname
func PromptForLoginDetails(loginDetails *LoginDetails) error {

	loginDetails.Hostname = promptFor("Hostname [%s]", loginDetails.Hostname)

	fmt.Println("To use saved username and password just hit enter.")

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
