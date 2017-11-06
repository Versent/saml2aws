// +build !windows

package shell

import (
	"os"
	"os/exec"
	"strings"
)

// ExecShellCmd exec shell command using the default shell
func ExecShellCmd(cmdline []string, envVars []string) error {

	c := strings.Join(cmdline, " ")

	cs := []string{"/bin/sh", "-c", c}
	cmd := exec.Command(cs[0], cs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), envVars...)

	return cmd.Run()
}
