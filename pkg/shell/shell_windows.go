package shell

import (
	"os"
	"os/exec"
)

// ExecShellCmd exec shell command using the cmd shell
func ExecShellCmd(cmdline []string, envVars []string) error {

	cs := []string{"cmd", "/C"}
	cs = append(cs, cmdline...)
	cmd := exec.Command(cs[0], cs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), envVars...)

	return cmd.Run()
}
