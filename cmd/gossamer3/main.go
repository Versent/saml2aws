package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"

	"github.com/GESkunkworks/gossamer3/cmd/gossamer3/commands"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/alecthomas/kingpin"
	"github.com/sirupsen/logrus"
)

var (
	// Version app version
	Version = "3.0.0"
)

// The `cmdLineList` type is used to make a `[]string` meet the requirements
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

	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	logrus.SetOutput(os.Stderr)
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})

	// the following avoids issues with powershell, and shells in windows reporting a program errors
	// because it has written to stderr
	if runtime.GOOS == "windows" {
		log.SetOutput(os.Stdout)
		logrus.SetOutput(os.Stdout)
	}

	app := kingpin.New("gossamer3", "A command line tool to help with SAML access to the AWS token service.")
	app.Version(Version)
	cfg.Version = Version

	// Settings not related to commands
	verbose := app.Flag("verbose", "Enable verbose logging").Bool()
	provider := app.Flag("provider", "This flag is obsolete. See: https://github.com/GESkunkworks/gossamer3#configuring-idp-accounts").Short('i').Enum("Ping")

	// Common (to all commands) settings
	commonFlags := new(flags.CommonFlags)
	app.Flag("config", "Path/filename of gossamer3 config file (env: GOSSAMER3_CONFIGFILE)").Envar("GOSSAMER3_CONFIGFILE").StringVar(&commonFlags.ConfigFile)
	app.Flag("idp-account", "The name of the configured IDP account. (env: GOSSAMER3_IDP_ACCOUNT)").Envar("GOSSAMER3_IDP_ACCOUNT").Short('a').Default("default").StringVar(&commonFlags.IdpAccount)
	app.Flag("idp-provider", "The configured IDP provider. (env: GOSSAMER3_IDP_PROVIDER)").Envar("GOSSAMER3_IDP_PROVIDER").EnumVar(&commonFlags.IdpProvider, "Ping")
	app.Flag("mfa", "The name of the mfa. (env: GOSSAMER3_MFA)").Envar("GOSSAMER3_MFA").StringVar(&commonFlags.MFA)
	app.Flag("mfa-device", "The name of the mfa device to use for authentication when multiple mfa devices are available. (env: GOSSAMER3_MFA_DEVICE)").Envar("GOSSAMER3_MFA_DEVICE").StringVar(&commonFlags.MFADevice)
	app.Flag("skip-verify", "Skip verification of server certificate. (env: GOSSAMER3_SKIP_VERIFY)").Envar("GOSSAMER3_SKIP_VERIFY").Short('s').BoolVar(&commonFlags.SkipVerify)
	app.Flag("url", "The URL of the SAML IDP server used to login. (env: GOSSAMER3_URL)").Envar("GOSSAMER3_URL").StringVar(&commonFlags.URL)
	app.Flag("username", "The username used to login. (env: GOSSAMER3_USERNAME)").Envar("GOSSAMER3_USERNAME").StringVar(&commonFlags.Username)
	app.Flag("password", "The password used to login. (env: GOSSAMER3_PASSWORD)").Envar("GOSSAMER3_PASSWORD").StringVar(&commonFlags.Password)
	app.Flag("mfa-token", "The current MFA token (supported in Keycloak, ADFS, GoogleApps). (env: GOSSAMER3_MFA_TOKEN)").Envar("GOSSAMER3_MFA_TOKEN").StringVar(&commonFlags.MFAToken)
	app.Flag("role", "The ARN of the role to assume. (env: GOSSAMER3_ROLE)").Envar("GOSSAMER3_ROLE").StringVar(&commonFlags.RoleArn)
	app.Flag("aws-urn", "The URN used by SAML when you login. (env: GOSSAMER3_AWS_URN)").Envar("GOSSAMER3_AWS_URN").StringVar(&commonFlags.AmazonWebservicesURN)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&commonFlags.SkipPrompt)
	app.Flag("session-duration", "The duration of your AWS Session. (env: GOSSAMER3_SESSION_DURATION)").Envar("GOSSAMER3_SESSION_DURATION").IntVar(&commonFlags.SessionDuration)
	app.Flag("disable-keychain", "Do not use keychain at all.").Envar("GOSSAMER3_DISABLE_KEYCHAIN").BoolVar(&commonFlags.DisableKeychain)
	app.Flag("region", "AWS region to use for API requests, e.g. us-east-1, us-gov-west-1, cn-north-1 (env: GOSSAMER3_REGION)").Envar("GOSSAMER3_REGION").Short('r').StringVar(&commonFlags.Region)
	app.Flag("quiet", "Do not show any log messages").Short('q').BoolVar(&commonFlags.Quiet)

	// `configure` command and settings
	cmdConfigure := app.Command("configure", "Configure a new IDP account.")
	cmdConfigure.Flag("profile", "The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)").Envar("GOSSAMER3_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	configFlags := commonFlags

	// `login` command and settings
	cmdLogin := app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	loginFlags := new(flags.LoginExecFlags)
	loginFlags.CommonFlags = commonFlags
	cmdLogin.Flag("profile", "The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)").Short('p').Envar("GOSSAMER3_PROFILE").StringVar(&commonFlags.Profile)
	cmdLogin.Flag("force", "Refresh credentials even if not expired.").BoolVar(&loginFlags.Force)
	cmdLogin.Flag("assume-child-role", "ARN of child role to assume before performing command (env: GOSSAMER3_ASSUME_CHILD_ROLE)").Envar("GOSSAMER3_ASSUME_CHILD_ROLE").StringVar(&loginFlags.AssumeChildRole)

	// `bulk-login` command and settings
	cmdBulkLogin := app.Command("bulk-login", "Bulk login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	bulkLoginFlags := new(flags.LoginExecFlags)
	cmdBulkLogin.Arg("config", "Bulk role configuration file").Required().StringVar(&bulkLoginFlags.BulkLoginConfig)
	bulkLoginFlags.CommonFlags = commonFlags
	cmdBulkLogin.Flag("force", "Refresh credentials even if not expired.").BoolVar(&bulkLoginFlags.Force)

	// `exec` command and settings
	cmdExec := app.Command("exec", "Exec the supplied command with env vars from STS token.")
	execFlags := new(flags.LoginExecFlags)
	execFlags.CommonFlags = commonFlags
	cmdExec.Flag("profile", "The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)").Envar("GOSSAMER3_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdExec.Flag("assume-child-role", "ARN of child role to assume before performing command (env: GOSSAMER3_ASSUME_CHILD_ROLE)").Envar("GOSSAMER3_ASSUME_CHILD_ROLE").StringVar(&execFlags.AssumeChildRole)
	cmdExec.Flag("exec-profile", "The AWS profile to utilize for command execution. Useful to allow the aws cli to perform secondary role assumption. (env: GOSSAMER3_EXEC_PROFILE)").Envar("GOSSAMER3_EXEC_PROFILE").StringVar(&execFlags.ExecProfile)
	cmdLine := buildCmdList(cmdExec.Arg("command", "The command to execute."))

	// `console` command and settings
	cmdConsole := app.Command("console", "Console will open the aws console after logging in.")
	consoleFlags := new(flags.ConsoleFlags)
	consoleFlags.LoginExecFlags = execFlags
	consoleFlags.LoginExecFlags.CommonFlags = commonFlags
	cmdConsole.Flag("exec-profile", "The AWS profile to utilize for console execution. (env: GOSSAMER3_EXEC_PROFILE)").Envar("GOSSAMER3_EXEC_PROFILE").StringVar(&consoleFlags.LoginExecFlags.ExecProfile)
	cmdConsole.Flag("assume-child-role", "ARN of child role to assume before logging into console (env: GOSSAMER3_ASSUME_CHILD_ROLE)").Envar("GOSSAMER3_ASSUME_CHILD_ROLE").StringVar(&consoleFlags.LoginExecFlags.AssumeChildRole)
	cmdConsole.Flag("profile", "The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)").Envar("GOSSAMER3_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdConsole.Flag("force", "Refresh credentials even if not expired.").BoolVar(&consoleFlags.LoginExecFlags.Force)
	cmdConsole.Flag("link", "Present link to AWS console instead of opening browser").BoolVar(&consoleFlags.Link)

	// `list` command and settings
	cmdListRoles := app.Command("list-roles", "List available role ARNs.")
	listRolesFlags := new(flags.LoginExecFlags)
	listRolesFlags.CommonFlags = commonFlags

	// `script` command and settings
	cmdScript := app.Command("script", "Emit a script that will export environment variables.")
	scriptFlags := new(flags.LoginExecFlags)
	scriptFlags.CommonFlags = commonFlags
	cmdScript.Flag("profile", "The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)").Envar("GOSSAMER3_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdScript.Flag("assume-child-role", "ARN of child role to assume before running script (env: GOSSAMER3_ASSUME_CHILD_ROLE)").Envar("GOSSAMER3_ASSUME_CHILD_ROLE").StringVar(&scriptFlags.AssumeChildRole)
	var shell string
	cmdScript.
		Flag("shell", "Type of shell environment. Options include: bash, powershell, fish").
		Default("bash").
		EnumVar(&shell, "bash", "powershell", "fish")

	// Trigger the parsing of the command line inputs via kingpin
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// will leave this here for a while during upgrade process
	if *provider != "" {
		log.Println("The --provider flag has been replaced with a new configure command. See https://github.com/GESkunkworks/gossamer3#adding-idp-accounts")
		os.Exit(1)
	}

	errtpl := "%v\n"
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
		errtpl = "%+v\n"
	} else if commonFlags.Quiet {
		logrus.SetLevel(logrus.ErrorLevel)
		log.SetOutput(ioutil.Discard)
	}

	// Set the default transport settings so all http clients will pick them up.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: commonFlags.SkipVerify}
	http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment

	logrus.WithField("command", command).Debug("Running")

	var err error
	switch command {
	case cmdScript.FullCommand():
		err = commands.Script(scriptFlags, shell)
	case cmdLogin.FullCommand():
		err = commands.Login(loginFlags)
	case cmdBulkLogin.FullCommand():
		err = commands.BulkLogin(bulkLoginFlags)
	case cmdExec.FullCommand():
		err = commands.Exec(execFlags, *cmdLine)
	case cmdConsole.FullCommand():
		err = commands.Console(consoleFlags)
	case cmdListRoles.FullCommand():
		err = commands.ListRoles(listRolesFlags)
	case cmdConfigure.FullCommand():
		err = commands.Configure(configFlags)
	}

	if err != nil {
		logrus.Errorf(errtpl, err)
		os.Exit(1)
	}
}
