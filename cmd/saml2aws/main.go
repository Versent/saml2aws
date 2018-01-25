package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/cmd/saml2aws/commands"
	"github.com/versent/saml2aws/pkg/flags"
)

var (
	// Version app version
	Version = "1.0.0"
)

// The `cmdLineList` type is used to make a `[]string` meet the requiements
// of the kingpin.Value interface
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

	app := kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")
	app.Version(Version)

	// Settings not related to commands
	verbose := app.Flag("verbose", "Enable verbose logging").Bool()
	provider := app.Flag("provider", "This flag it is obsolete see https://github.com/Versent/saml2aws#adding-idp-accounts.").Short('i').Enum("ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "KeyCloak")

	// Common (to all commands) settings
	commonFlags := new(flags.CommonFlags)
	app.Flag("idp-account", "The name of the configured IDP account").Short('a').Default("default").StringVar(&commonFlags.IdpAccount)
	app.Flag("idp-provider", "The configured IDP provider").EnumVar(&commonFlags.IdpProvider, "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "KeyCloak")
	app.Flag("mfa", "The name of the mfa").EnumVar(&commonFlags.MFA, "Auto", "VIP")
	app.Flag("skip-verify", "Skip verification of server certificate.").Short('s').BoolVar(&commonFlags.SkipVerify)
	app.Flag("url", "The URL of the SAML IDP server used to login.").StringVar(&commonFlags.URL)
	app.Flag("username", "The username used to login.").Envar("SAML2AWS_USERNAME").StringVar(&commonFlags.Username)
	app.Flag("role", "The ARN of the role to assume.").StringVar(&commonFlags.RoleArn)
	app.Flag("aws-urn", "The URN used by SAML when you login.").StringVar(&commonFlags.AmazonWebservicesURN)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&commonFlags.SkipPrompt)

	// `configure` command and settings
	cmdConfigure := app.Command("configure", "Configure a new IDP account.")
	configFlags := commonFlags

	// `login` command and settings
	cmdLogin := app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	loginFlags := new(flags.LoginExecFlags)
	loginFlags.CommonFlags = commonFlags
	cmdLogin.Flag("password", "The password used to login.").Envar("SAML2AWS_PASSWORD").StringVar(&loginFlags.Password)
	cmdLogin.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").StringVar(&loginFlags.Profile)

	// `exec` command and settings
	cmdExec := app.Command("exec", "Exec the supplied command with env vars from STS token.")
	execFlags := new(flags.LoginExecFlags)
	execFlags.CommonFlags = commonFlags
	cmdExec.Flag("password", "The password used to login.").Envar("SAML2AWS_PASSWORD").StringVar(&execFlags.Password)
	cmdExec.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").StringVar(&execFlags.Profile)
	cmdLine := buildCmdList(cmdExec.Arg("command", "The command to execute."))

	// `list` command and settings
	cmdListRoles := app.Command("list-roles", "List available role ARNs.")
	listRolesFlags := new(flags.LoginExecFlags)
	listRolesFlags.CommonFlags = commonFlags
	cmdListRoles.Flag("password", "The password used to login.").Envar("SAML2AWS_PASSWORD").StringVar(&execFlags.Password)

	// Trigger the parsing of the command line inputs via kingpin
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// will leave this here for a while during upgrade process
	if *provider != "" {
		fmt.Println("The --provider flag has been replaced with a new configure command. See https://github.com/Versent/saml2aws#adding-idp-accounts")
		os.Exit(1)
	}

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.WithField("command", command).Debug("Running")

	var err error
	switch command {
	case cmdLogin.FullCommand():
		err = commands.Login(loginFlags)
	case cmdExec.FullCommand():
		err = commands.Exec(execFlags, *cmdLine)
	case cmdListRoles.FullCommand():
		err = commands.ListRoles(listRolesFlags)
	case cmdConfigure.FullCommand():
		err = commands.Configure(configFlags)
	}

	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
