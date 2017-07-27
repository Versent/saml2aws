package main

import (
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/versent/saml2aws/cmd/saml2aws/commands"
)

var (
	app = kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")

	cmdLogin = app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	cmdExec  = app.Command("exec", "Exec the supplied command with env vars from STS token.")
	cmdLine  = buildCmdList(cmdExec.Arg("command", "The command to execute."))

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

func configureLoginFlags(app *kingpin.Application) *commands.LoginFlags {
	c := &commands.LoginFlags{}

	app.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").StringVar(&c.Profile)
	app.Flag("skip-verify", "Skip verification of server certificate.").Short('s').BoolVar(&c.SkipVerify)
	app.Flag("provider", "The type of SAML IDP provider.").Short('i').Default("ADFS").EnumVar(&c.Provider, "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "KeyCloak")
	app.Flag("hostname", "The hostname of the SAML IDP server used to login.").StringVar(&c.Hostname)
	app.Flag("username", "The username used to login.").StringVar(&c.Username)
	app.Flag("password", "The password used to login.").Envar("SAML2AWS_PASSWORD").StringVar(&c.Password)
	app.Flag("role", "The ARN of the role to assume.").StringVar(&c.RoleArn)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&c.SkipPrompt)

	return c
}

func main() {
	log.SetFlags(log.Lshortfile)

	app.Version(Version)

	lc := configureLoginFlags(app)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var err error

	switch command {
	case cmdLogin.FullCommand():
		err = commands.Login(lc)
	case cmdExec.FullCommand():
		err = commands.Exec(lc, *cmdLine)
	}

	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
