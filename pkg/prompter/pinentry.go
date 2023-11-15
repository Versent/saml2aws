package prompter

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

const (
	defaultPinentryDialog string = "Security token [%s]"
)

// PinentryRunner is the interface for pinentry to run itself
type PinentryRunner interface {
	Run(string) (string, error)
}

// RealPinentryRunner is the concrete implementation of PinentryRunner
type RealPinentryRunner struct {
	PinentryBin string
}

// PinentryPrompter is a concrete implementation of the Prompter interface.
// It uses the default Cli under the hood, except for RequestSecurityCode, where
// it uses any _pinentry_ binary to capture the security code.
// Its purpose is mainly to capture the TOTP code outside of the TTY, and thus
// making it possible to use TOTP with the credential process.
// https://github.com/Versent/saml2aws#using-saml2aws-as-credential-process
type PinentryPrompter struct {
	Runner          PinentryRunner
	DefaultPrompter Prompter
}

// NewPinentryPrompter is a factory for PinentryPrompter
func NewPinentryPrompter(bin string) *PinentryPrompter {
	return &PinentryPrompter{Runner: NewRealPinentryRunner(bin), DefaultPrompter: NewCli()}
}

// NewRealPinentryRunner is a factory for RealPinentryRunner
func NewRealPinentryRunner(bin string) *RealPinentryRunner {
	return &RealPinentryRunner{PinentryBin: bin}
}

// RequestSecurityCode for PinentryPrompter is creating a query for pinentry
// and sends it to the pinentry bin.
func (p *PinentryPrompter) RequestSecurityCode(pattern string) (output string) {
	commandTemplate := "SETPROMPT %s\nGETPIN\n"
	prompt := fmt.Sprintf(defaultPinentryDialog, pattern)
	command := fmt.Sprintf(commandTemplate, prompt)
	if output, err := p.Runner.Run(command); err != nil {
		return ""
	} else {
		return output
	}
}

// ChooseWithDefault is running the default CLI ChooseWithDefault
func (p *PinentryPrompter) ChooseWithDefault(prompt string, def string, choices []string) (string, error) {
	return p.DefaultPrompter.ChooseWithDefault(prompt, def, choices)
}

// Choose is running the default CLI Choose
func (p *PinentryPrompter) Choose(pr string, options []string) int {
	return p.DefaultPrompter.Choose(pr, options)
}

// StringRequired is runniner the default Cli StringRequired
func (p *PinentryPrompter) StringRequired(pr string) string {
	return p.DefaultPrompter.StringRequired(pr)
}

// String is runniner the default Cli String
func (p *PinentryPrompter) String(pr string, defaultValue string) string {
	return p.DefaultPrompter.String(pr, defaultValue)
}

// Password is runniner the default Cli Password
func (p *PinentryPrompter) Password(pr string) string {
	return p.DefaultPrompter.Password(pr)
}
// Display is runniner the default Cli Display
func (p *PinentryPrompter) Display(pr string) {
	p.DefaultPrompter.Display(pr)
}
// Run wraps a pinentry run. It sends the query to pinentry via stdin and
// reads its stdout to determine the user PIN.
// Pinentry uses an Assuan protocol
func (r *RealPinentryRunner) Run(command string) (output string, err error) {
	cmd := exec.Command(r.PinentryBin, "--ttyname", "/dev/tty")
	cmd.Stdin = strings.NewReader(command)
	out, _ := cmd.StdoutPipe()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = cmd.Run()
		// fmt.Println(err)
		wg.Done()
	}()

	output, err = ParseResults(out)
	wg.Wait()
	return output, err
}

// ParseResults parses the standard output of the pinentry command and determine the
// user input, or wheter the program yielded any error
func ParseResults(pinEntryOutput io.Reader) (output string, err error) {
	scanner := bufio.NewScanner(pinEntryOutput)
	for scanner.Scan() {
		line := scanner.Text()
		// fmt.Println(line)
		if strings.HasPrefix(line, "D ") {
			output = line[2:]
		}
		if strings.HasPrefix(line, "ERR ") {
			return "", fmt.Errorf("Error while running pinentry: %s", line[4:])
		}
	}

	return output, err
}
