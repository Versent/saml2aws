package prompter

import prompt "github.com/segmentio/go-prompt"

// Prompter handles prompting user for input
type Prompter interface {
	RequestSecurityCode(pattern string) string
	Choice(prompt string, options []string) string
	StringRequired(pr string) string
}

// CliPrompter used to prompt for cli input
type CliPrompter struct {
}

// NewCli builds a new cli prompter
func NewCli() Prompter {
	return &CliPrompter{}
}

// RequestSecurityCode request a security code to be entered by the user
func (cli *CliPrompter) RequestSecurityCode(pattern string) string {
	return prompt.StringRequired("\nSecurity Token [%s]\n", pattern)
}

// Choice given the choice return the option selected
func (cli *CliPrompter) Choice(pr string, options []string) string {
	selected := prompt.Choose(pr, options)
	return options[selected]
}

// StringRequired prompt for string which is required
func (cli *CliPrompter) StringRequired(pr string) string {
	return prompt.StringRequired(pr)
}
