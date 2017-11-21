package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/cmd/saml2aws/commands"
)

var (
	app = kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")

	verbose = app.Flag("verbose", "Enable verbose logging").Bool()

	cmdLogin     = app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	cmdExec      = app.Command("exec", "Exec the supplied command with env vars from STS token.")
	cmdConfigure = app.Command("configure", "Configure a new IDP account.")
	cmdLine      = buildCmdList(cmdExec.Arg("command", "The command to execute."))

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

	app.Flag("idp-account", "The name of the configured IDP account").Short('a').Default("default").StringVar(&c.IdpAccount)
	app.Flag("idp-provider", "The configured IDP provider").EnumVar(&c.IdpProvider, "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "KeyCloak")
	app.Flag("mfa", "The name of the mfa").Default("Auto").StringVar(&c.MFA)
	app.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").StringVar(&c.Profile)
	app.Flag("skip-verify", "Skip verification of server certificate.").Short('s').BoolVar(&c.SkipVerify)
	// app.Flag("timeout", "Override the default HTTP client timeout in seconds.").Short('t').IntVar(&c.Timeout)
	// app.Flag("provider", "The type of SAML IDP provider.").Short('i').Default("ADFS").EnumVar(&c.Provider, "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "KeyCloak")
	app.Flag("url", "The URL of the SAML IDP server used to login.").StringVar(&c.URL)
	app.Flag("username", "The username used to login.").StringVar(&c.Username)
	app.Flag("password", "The password used to login.").Envar("SAML2AWS_PASSWORD").StringVar(&c.Password)
	app.Flag("role", "The ARN of the role to assume.").StringVar(&c.RoleArn)
	app.Flag("aws-urn", "The URN used by SAML when you login.").StringVar(&c.AmazonWebservicesURN)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&c.SkipPrompt)

	return c
}

func main() {

	app.Version(Version)

	lc := configureLoginFlags(app)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var err error

	logrus.WithField("command", command).Debug("Running")

	switch command {
	case cmdLogin.FullCommand():
		err = commands.Login(lc)
	case cmdExec.FullCommand():
		err = commands.Exec(lc, *cmdLine)
	case cmdConfigure.FullCommand():
		err = commands.Configure(lc, *cmdLine)
	}

	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
