package main

import (
	"log"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/versent/saml2aws/cmd/saml2aws/commands"
)

var (
	app = kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")

	// /verbose      = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	profileName = app.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").String()
	skipVerify  = app.Flag("skip-verify", "Skip verification of server certificate.").Short('s').Bool()

	cmdLogin = app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")

	cmdConfigure = app.Command("configure", "Configure Login profile detail (Provider, Hostname, Username)")

	cmdExec = app.Command("exec", "Exec the supplied command with env vars from STS token.")
	cmdLine = buildCmdList(cmdExec.Arg("command", "The command to execute."))

	// Version app version
	Version = "1.0.0"
)

type cmdLineList []string

func (i *cmdLineList) Set(value string) error {
	*i = append(*i, value)

	return nil
}

func (i *cmdLineList) String() string {
	return ""
}

func (i *cmdLineList) IsCumulative() bool {
	return true
}

func buildCmdList(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*cmdLineList)(target))
	return
}

func main() {
	log.SetFlags(log.Lshortfile)

	app.Version(Version)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var err error

	switch command {
	case cmdLogin.FullCommand():
		err = commands.Login(*profileName, *skipVerify)
	case cmdExec.FullCommand():
		err = commands.Exec(*profileName, *skipVerify, *cmdLine)
	case cmdConfigure.FullCommand():
		err = commands.Configure(*profileName)
	}
	if err != nil {
		log.Fatal(err)
	}
}
