package prompter

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/AlecAivazis/survey/v2/terminal"

	survey "github.com/AlecAivazis/survey/v2"
)

// CliPrompter used to prompt for cli input
type CliPrompter struct {
}

// NewCli builds a new cli prompter
func NewCli() *CliPrompter {
	return &CliPrompter{}
}

func errorHandler(err error) {
	if err == terminal.InterruptErr {
		os.Exit(0)
	} else if err != nil {
		logrus.Fatalln(err.Error())
	}
}

// RequestSecurityCode request a security code to be entered by the user
func (cli *CliPrompter) RequestSecurityCode(pattern string) string {
	token := ""
	prompt := &survey.Password{
		Message: fmt.Sprintf("Security Token [%s]", pattern),
	}
	err := survey.AskOne(prompt, &token, survey.WithValidator(survey.Required))
	errorHandler(err)
	return token
}

// ChooseWithDefault given the choice return the option selected with a default
func (cli *CliPrompter) ChooseWithDefault(pr string, defaultValue string, options []string) (string, error) {
	selected := ""
	prompt := &survey.Select{
		Message: pr,
		Options: options,
		Default: defaultValue,
	}
	err := survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required))
	errorHandler(err)

	// return the selected element index
	for i, option := range options {
		if selected == option {
			return options[i], nil
		}
	}
	return "", errors.New("bad input")
}

// Choose given the choice return the option selected
func (cli *CliPrompter) Choose(pr string, options []string) int {
	selected := ""
	prompt := &survey.Select{
		Message: pr,
		Options: options,
	}
	err := survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required))
	errorHandler(err)

	// return the selected element index
	for i, option := range options {
		if selected == option {
			return i
		}
	}
	return 0
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) String(pr string, defaultValue string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
		Default: defaultValue,
	}
	err := survey.AskOne(prompt, &val)
	errorHandler(err)
	return val
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) StringRequired(pr string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
	}
	err := survey.AskOne(prompt, &val, survey.WithValidator(survey.Required))
	errorHandler(err)
	return val
}

// Password prompt for password which is required
func (cli *CliPrompter) Password(pr string) string {
	val := ""
	prompt := &survey.Password{
		Message: pr,
	}
	err := survey.AskOne(prompt, &val)
	errorHandler(err)
	return val
}
