package saml2aws

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/segmentio/go-prompt"
)

var (
	// ErrMissingUsername returned when the user fails to enter a username
	ErrMissingUsername = fmt.Errorf("Missing or invalid username entered")
)

// PromptForLoginCreds prompt the user to present their username and password
func PromptForLoginCreds(username string) (*LoginCreds, error) {

	var usernameEntered string

	// do while
	for ok := true; ok; ok = strings.TrimSpace(username) == "" && strings.TrimSpace(usernameEntered) == "" {
		usernameEntered = prompt.String("Username [%s]", username)
	}

	if usernameEntered == "" {
		usernameEntered = username
	}

	password := prompt.PasswordMasked("Password")

	fmt.Println("")

	return &LoginCreds{strings.TrimSpace(usernameEntered), strings.TrimSpace(password)}, nil
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func PromptForAWSRoleSelection(roles []string) (*AWSRole, error) {

	if len(roles) == 1 {
		tok := strings.Split(roles[0], ",")

		return &AWSRole{tok[0], tok[1]}, nil
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Please choose the role you would like to assume: ")

	for i, role := range roles {
		fmt.Println("[", i, "]: ", strings.Split(role, ",")[1])
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

	selectedRole := roles[v]

	tok := strings.Split(selectedRole, ",")

	return &AWSRole{tok[1], tok[0]}, nil
}
