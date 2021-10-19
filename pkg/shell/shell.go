// +build !windows

package shell

import (
	"os"
	"os/exec"
)

// ExecShellCmd exec shell command using the default shell
func ExecShellCmd(cmdline []string, envVars []string) error {
	return prepCmd(cmdline, envVars).Run()
}

func prepCmd(cs []string, envVars []string) *exec.Cmd {
	cmd := exec.Command(cs[0], cs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), envVars...)
	return cmd
}
