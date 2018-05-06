package prompter

var defaultPrompter Prompter = NewCli()

// Prompter handles prompting user for input
type Prompter interface {
	RequestSecurityCode(string) string
	ChooseWithDefault(string, string, []string) (string, error)
	Choose(string, []string) int
	StringRequired(string) string
	String(string, string) string
	Password(string) string
}

// SetPrompter configure an aternate prompter to the default one
func SetPrompter(prmpt Prompter) {
	defaultPrompter = prmpt
}

// RequestSecurityCode request a security code to be entered by the user
func RequestSecurityCode(pattern string) string {
	return defaultPrompter.RequestSecurityCode(pattern)
}

// ChooseWithDefault given the choice return the option selected with a default
func ChooseWithDefault(pr string, defaultValue string, options []string) (string, error) {
	return defaultPrompter.ChooseWithDefault(pr, defaultValue, options)
}

// Choose given the choice return the option selected
func Choose(pr string, options []string) int {
	return defaultPrompter.Choose(pr, options)
}

// StringRequired prompt for string which is required
func StringRequired(pr string) string {
	return defaultPrompter.StringRequired(pr)
}

// String prompt for string which is required
func String(pr string, defaultValue string) string {
	return defaultPrompter.String(pr, defaultValue)
}

// Password prompt for password which is required
func Password(pr string) string {
	return defaultPrompter.Password(pr)
}
