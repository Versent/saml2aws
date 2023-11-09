package prompter

import (
	"errors"
	"fmt"
	"os"

	survey "github.com/AlecAivazis/survey/v2"
	survey_terminal "github.com/AlecAivazis/survey/v2/terminal"
)

// outputWriter is where for all prompts will be printed. Defaults to os.Stder.
var outputWriter survey_terminal.FileWriter = os.Stderr

// CliPrompter used to prompt for cli input
type CliPrompter struct {
}

// SetOutputWriter sets the output writer to use for all survey operations
func SetOutputWriter(writer survey_terminal.FileWriter) {
	outputWriter = writer
}

// stdioOption returns the IO option to use for survey functions
func stdioOption() survey.AskOpt {
	return survey.WithStdio(os.Stdin, outputWriter, os.Stderr)
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
	_ = survey.AskOne(prompt, &token, survey.WithValidator(survey.Required), stdioOption())
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
	_ = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required), stdioOption())

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
	_ = survey.AskOne(prompt, &selected, survey.WithValidator(survey.Required), stdioOption())

	// return the selected element index
	for i, option := range options {
		if selected == option {
			return i
		}
	}
	return 0
}

// String prompt for string with a default
func (cli *CliPrompter) String(pr string, defaultValue string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
		Default: defaultValue,
	}
	_ = survey.AskOne(prompt, &val, stdioOption())
	return val
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) StringRequired(pr string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
	}
	_ = survey.AskOne(prompt, &val, survey.WithValidator(survey.Required), stdioOption())
	return val
}

// Password prompt for password which is required
func (cli *CliPrompter) Password(pr string) string {
	val := ""
	prompt := &survey.Password{
		Message: pr,
	}
	_ = survey.AskOne(prompt, &val, stdioOption())
	return val
}
