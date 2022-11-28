package prompter

import (
	"errors"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"os"
)

// CliPrompter used to prompt for cli input
type CliPrompter struct {
	stdErrOutput bool
}

// NewCli builds a new cli prompter
func NewCli(stdErrOutput bool) *CliPrompter {
	return &CliPrompter{stdErrOutput}
}

// RequestSecurityCode request a security code to be entered by the user
func (cli *CliPrompter) RequestSecurityCode(pattern string) string {
	token := ""
	prompt := &survey.Input{
		Message: fmt.Sprintf("Security Token [%s]", pattern),
	}
	opts := []survey.AskOpt{survey.WithValidator(survey.Required)}
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &token, opts...)
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
	opts := []survey.AskOpt{survey.WithValidator(survey.Required)}
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &selected, opts...)

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
	opts := []survey.AskOpt{survey.WithValidator(survey.Required)}
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &selected, opts...)

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
	var opts []survey.AskOpt
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &val, opts...)
	return val
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) StringRequired(pr string) string {
	val := ""
	prompt := &survey.Input{
		Message: pr,
	}
	opts := []survey.AskOpt{survey.WithValidator(survey.Required)}
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &val, opts...)
	return val
}

// Password prompt for password which is required
func (cli *CliPrompter) Password(pr string) string {
	val := ""
	prompt := &survey.Password{
		Message: pr,
	}
	var opts []survey.AskOpt
	if cli.stdErrOutput {
		opts = append(opts, survey.WithStdio(os.Stdin, os.Stderr, os.Stdin))
	}
	_ = survey.AskOne(prompt, &val, opts...)
	return val
}
