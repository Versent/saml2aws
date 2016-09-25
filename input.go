package saml2aws

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/segmentio/go-prompt"
)


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
