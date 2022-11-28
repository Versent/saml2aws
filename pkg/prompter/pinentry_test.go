package prompter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// creates a fake runner so we can perform unit tests
type FakePinentryRunner struct {
	HasRun             bool
	FakeOutput         string
	FakePinentryOutput string
	PassedInput        string
}

func (f *FakePinentryRunner) Run(cmd string) (string, error) {
	f.PassedInput = cmd
	f.HasRun = true
	if f.FakeOutput != "" {
		return f.FakeOutput, nil
	}
	if f.FakePinentryOutput != "" {
		reader := strings.NewReader(f.FakePinentryOutput)
		return ParseResults(reader)
	}
	return f.FakeOutput, nil
}

// FakeDefaultPrompter is a Mock prompter
type FakeDefaultPrompter struct {
	CalledRequestSecurityCode bool
	CalledChoose              bool
	CalledChooseWithDefault   bool
	CalledString              bool
	CalledStringRequired      bool
	CalledPassword            bool
}

// all the functions to implement the Prompter interface
func (f *FakeDefaultPrompter) RequestSecurityCode(p string) string {
	f.CalledRequestSecurityCode = true
	return ""
}
func (f *FakeDefaultPrompter) Choose(p string, option []string) int {
	f.CalledChoose = true
	return 0
}
func (f *FakeDefaultPrompter) ChooseWithDefault(p string, d string, c []string) (string, error) {
	f.CalledChooseWithDefault = true
	return "", nil
}
func (f *FakeDefaultPrompter) String(p string, defaultValue string) string {
	f.CalledString = true
	return ""
}
func (f *FakeDefaultPrompter) StringRequired(p string) string {
	f.CalledStringRequired = true
	return ""
}
func (f *FakeDefaultPrompter) Password(p string) string {
	f.CalledPassword = true
	return ""
}

func TestValidateAndSetPrompterShouldFailWithWrongInput(t *testing.T) {

	// backing up the current prompters for the other tests
	oldPrompter := ActivePrompter
	defer func() { ActivePrompter = oldPrompter }()

	errPrompts := []string{"abcde", "invalid", "prompt", "    ", "pinentryfake"}
	for _, errPrompt := range errPrompts {
		err := ValidateAndSetPrompter(errPrompt)
		assert.Error(t, err)
	}

}
func TestValidateAndSetPrompterShouldWorkWithInputForCli(t *testing.T) {

	// backing up the current prompters for the other tests
	oldPrompter := ActivePrompter
	defer func() { ActivePrompter = oldPrompter }()

	errPrompts := []string{"", "default", "survey"}
	for _, errPrompt := range errPrompts {
		err := ValidateAndSetPrompter(errPrompt)
		assert.NoError(t, err)
		assert.IsType(t, ActivePrompter, NewCli(false))
	}

}
func TestValidateAndSetPrompterShouldWorkWithInputForPinentry(t *testing.T) {

	// backing up the current prompters for the other tests
	oldPrompter := ActivePrompter
	defer func() { ActivePrompter = oldPrompter }()

	errPrompts := []string{"pinentry", "pinentry-tty", "pinentry-mac", "pinentry-gnome3"}
	for _, errPrompt := range errPrompts {
		err := ValidateAndSetPrompter(errPrompt)
		assert.NoError(t, err)
		assert.IsType(t, ActivePrompter, &PinentryPrompter{})
	}

}

func TestChecksPinentryPrompterDefault(t *testing.T) {
	p := &PinentryPrompter{}
	fakeDefaultPrompter := &FakeDefaultPrompter{}
	p.DefaultPrompter = fakeDefaultPrompter

	_ = p.Choose("random", []string{"1", "2"})
	assert.True(t, fakeDefaultPrompter.CalledChoose)

	_, _ = p.ChooseWithDefault("random", "random", []string{"1", "2"})
	assert.True(t, fakeDefaultPrompter.CalledChooseWithDefault)

	_ = p.String("random", "random")
	assert.True(t, fakeDefaultPrompter.CalledString)

	_ = p.StringRequired("random")
	assert.True(t, fakeDefaultPrompter.CalledStringRequired)

	_ = p.Password("random")
	assert.True(t, fakeDefaultPrompter.CalledPassword)
}

func TestChecksPinentryPrompterCallsPinentryForRequestSecurityCode(t *testing.T) {
	p := &PinentryPrompter{}
	runner := &FakePinentryRunner{}
	p.Runner = runner
	runner.FakeOutput = "random_code"
	pinentryOutput := p.RequestSecurityCode("000000")

	assert.True(t, runner.HasRun)
	assert.Equal(t, pinentryOutput, "random_code")
	assert.Equal(t, runner.PassedInput, "SETPROMPT Security token [000000]\nGETPIN\n")

}

func TestChecksPinentryPrompterReturnsRightCodeGivenFakePinentryOutput(t *testing.T) {
	p := &PinentryPrompter{}
	runner := &FakePinentryRunner{}
	p.Runner = runner
	runner.FakePinentryOutput = "OK This line should get ignored\nOK This line should too\nD 654321\nOK Final\n"
	pinentryOutput := p.RequestSecurityCode("000000")

	assert.True(t, runner.HasRun)
	assert.Equal(t, pinentryOutput, "654321")

}

func TestChecksPinentryPrompterReturnsNoCodeGivenErroneousFakePinentryOutput(t *testing.T) {
	p := &PinentryPrompter{}
	runner := &FakePinentryRunner{}
	p.Runner = runner
	runner.FakePinentryOutput = "OK This line should get ignored\nOK This line should too\nERR This is an error\nD 654321\nOK Final\n"
	pinentryOutput := p.RequestSecurityCode("000000")

	assert.True(t, runner.HasRun)
	assert.Equal(t, pinentryOutput, "")
}

func TestParseOutputShouldThrowError(t *testing.T) {

	input := strings.NewReader("OK Ignore this line\nERR This is an error\nD This result should be ignored\nOK this is irrelevant\n")
	output, err := ParseResults(input)

	assert.Error(t, err)
	assert.Equal(t, output, "")
}

func TestParseOutputShouldReturnCorrectOutput(t *testing.T) {

	input := strings.NewReader("OK Ignore this line\nD THISISTHERETURN\nOK this is irrelevant\n")
	output, err := ParseResults(input)

	assert.NoError(t, err)
	assert.Equal(t, output, "THISISTHERETURN")
}
