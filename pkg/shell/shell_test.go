//go:build !windows
// +build !windows

package shell

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecShellCmd(t *testing.T) {

	err := ExecShellCmd([]string{"echo", "$TESTTEST"}, []string{"TESTTEST=123"})

	assert.Nil(t, err)

}

func TestPrepCmd(t *testing.T) {

	cmd := prepCmd([]string{"echo", "some$TESTTEST", "one   two"}, []string{"TESTTEST=123"})

	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	assert.Nil(t, err)

	assert.Equal(t, "some$TESTTEST one   two\n", out.String(), "no eval, spaces preserved")
}

func TestPrepCmdShell(t *testing.T) {
	cmd := prepCmd([]string{"sh", "-c", "echo some$TESTTEST one   two"}, []string{"TESTTEST=123"})

	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	assert.Nil(t, err)

	assert.Equal(t, "some123 one two\n", out.String(), "var evaled, spaces squashed")

}
