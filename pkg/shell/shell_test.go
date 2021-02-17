// +build !windows

package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecShellCmd(t *testing.T) {

	err := ExecShellCmd([]string{"echo", "$TESTTEST"}, []string{"TESTTEST=123"})

	assert.Nil(t, err)

}
