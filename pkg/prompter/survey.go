package prompter

import (
	"errors"
	"fmt"

	survey "github.com/AlecAivazis/survey/v2"
)

// CliPrompter used to prompt for cli input
type CliPrompter struct {
}

// NewCli builds a new cli prompter
func NewCli() *CliPrompter {
	return &CliPrompter{}
}

// RequestSecurityCode request a security code to be entered by the user
func (cli *CliPrompter) RequestSecurityCode(pattern string) string {
	token := ""
	prompt := &survey.Input{
		Message: fmt.Sprintf("Security Token [%s]", pattern),
	}
	_ = survey.AskOne(prompt, &token, survey.WithValidator(survey.Required))
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
	_ = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required))

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
	_ = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required))

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
	_ = survey.AskOne(prompt, &val)
	return val
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) StringRequired(pr string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
	}
	_ = survey.AskOne(prompt, &val, survey.WithValidator(survey.Required))
	return val
}

// Password prompt for password which is required
func (cli *CliPrompter) Password(pr string) string {
	val := ""
	prompt := &survey.Password{
		Message: pr,
	}
	_ = survey.AskOne(prompt, &val)
	return val
}
