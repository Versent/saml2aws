package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/alecthomas/kingpin"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/cmd/saml2aws/commands"
	"github.com/versent/saml2aws/v2/pkg/flags"
)

var (
	// Version app version
	Version = "1.0.0"
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

	// the following avoids issues with powershell, and shells in windows reporting a program errors
	// because it has written to stderr
	if runtime.GOOS == "windows" {
		log.SetOutput(os.Stdout)
		logrus.SetOutput(os.Stdout)
	}

	app := kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")
	app.Version(Version)

	// Settings not related to commands
	verbose := app.Flag("verbose", "Enable verbose logging").Bool()
	quiet := app.Flag("quiet", "silences logs").Bool()

	provider := app.Flag("provider", "This flag is obsolete. See: https://github.com/versent/saml2aws/v2#configuring-idp-accounts").Short('i').Enum("Akamai", "AzureAD", "ADFS", "ADFS2", "Ping", "JumpCloud", "Okta", "OneLogin", "PSU", "KeyCloak")

	// Common (to all commands) settings
	commonFlags := new(flags.CommonFlags)
	app.Flag("config", "Path/filename of saml2aws config file (env: SAML2AWS_CONFIGFILE)").Envar("SAML2AWS_CONFIGFILE").StringVar(&commonFlags.ConfigFile)
	app.Flag("idp-account", "The name of the configured IDP account. (env: SAML2AWS_IDP_ACCOUNT)").Envar("SAML2AWS_IDP_ACCOUNT").Short('a').Default("default").StringVar(&commonFlags.IdpAccount)
	app.Flag("idp-provider", "The configured IDP provider. (env: SAML2AWS_IDP_PROVIDER)").Envar("SAML2AWS_IDP_PROVIDER").EnumVar(&commonFlags.IdpProvider, "Akamai", "AzureAD", "ADFS", "ADFS2", "GoogleApps", "Ping", "JumpCloud", "Okta", "OneLogin", "PSU", "KeyCloak", "F5APM", "Shibboleth", "ShibbolethECP", "NetIQ")
	app.Flag("mfa", "The name of the mfa. (env: SAML2AWS_MFA)").Envar("SAML2AWS_MFA").StringVar(&commonFlags.MFA)
	app.Flag("skip-verify", "Skip verification of server certificate. (env: SAML2AWS_SKIP_VERIFY)").Envar("SAML2AWS_SKIP_VERIFY").Short('s').BoolVar(&commonFlags.SkipVerify)
	app.Flag("url", "The URL of the SAML IDP server used to login. (env: SAML2AWS_URL)").Envar("SAML2AWS_URL").StringVar(&commonFlags.URL)
	app.Flag("username", "The username used to login. (env: SAML2AWS_USERNAME)").Envar("SAML2AWS_USERNAME").StringVar(&commonFlags.Username)
	app.Flag("password", "The password used to login. (env: SAML2AWS_PASSWORD)").Envar("SAML2AWS_PASSWORD").StringVar(&commonFlags.Password)
	app.Flag("mfa-token", "The current MFA token (supported in Keycloak, ADFS, GoogleApps). (env: SAML2AWS_MFA_TOKEN)").Envar("SAML2AWS_MFA_TOKEN").StringVar(&commonFlags.MFAToken)
	app.Flag("role", "The ARN of the role to assume. (env: SAML2AWS_ROLE)").Envar("SAML2AWS_ROLE").StringVar(&commonFlags.RoleArn)
	app.Flag("aws-urn", "The URN used by SAML when you login. (env: SAML2AWS_AWS_URN)").Envar("SAML2AWS_AWS_URN").StringVar(&commonFlags.AmazonWebservicesURN)
	app.Flag("skip-prompt", "Skip prompting for parameters during login.").BoolVar(&commonFlags.SkipPrompt)
	app.Flag("session-duration", "The duration of your AWS Session. (env: SAML2AWS_SESSION_DURATION)").Envar("SAML2AWS_SESSION_DURATION").IntVar(&commonFlags.SessionDuration)
	app.Flag("disable-keychain", "Do not use keychain at all.").Envar("SAML2AWS_DISABLE_KEYCHAIN").BoolVar(&commonFlags.DisableKeychain)
	app.Flag("region", "AWS region to use for API requests, e.g. us-east-1, us-gov-west-1, cn-north-1 (env: SAML2AWS_REGION)").Envar("SAML2AWS_REGION").Short('r').StringVar(&commonFlags.Region)

	// `configure` command and settings
	cmdConfigure := app.Command("configure", "Configure a new IDP account.")
	cmdConfigure.Flag("app-id", "OneLogin app id required for SAML assertion. (env: ONELOGIN_APP_ID)").Envar("ONELOGIN_APP_ID").StringVar(&commonFlags.AppID)
	cmdConfigure.Flag("client-id", "OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)").Envar("ONELOGIN_CLIENT_ID").StringVar(&commonFlags.ClientID)
	cmdConfigure.Flag("client-secret", "OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)").Envar("ONELOGIN_CLIENT_SECRET").StringVar(&commonFlags.ClientSecret)
	cmdConfigure.Flag("subdomain", "OneLogin subdomain of your company account. (env: ONELOGIN_SUBDOMAIN)").Envar("ONELOGIN_SUBDOMAIN").StringVar(&commonFlags.Subdomain)
	cmdConfigure.Flag("profile", "The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)").Envar("SAML2AWS_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdConfigure.Flag("resource-id", "F5APM SAML resource ID of your company account. (env: SAML2AWS_F5APM_RESOURCE_ID)").Envar("SAML2AWS_F5APM_RESOURCE_ID").StringVar(&commonFlags.ResourceID)
	cmdConfigure.Flag("credentials-file", "The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)").Envar("SAML2AWS_CREDENTIALS_FILE").StringVar(&commonFlags.CredentialsFile)
	configFlags := commonFlags

	// `login` command and settings
	cmdLogin := app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")
	loginFlags := new(flags.LoginExecFlags)
	loginFlags.CommonFlags = commonFlags
	cmdLogin.Flag("profile", "The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)").Short('p').Envar("SAML2AWS_PROFILE").StringVar(&commonFlags.Profile)
	cmdLogin.Flag("duo-mfa-option", "The MFA option you want to use to authenticate with").Envar("SAML2AWS_DUO_MFA_OPTION").EnumVar(&loginFlags.DuoMFAOption, "Passcode", "Duo Push")
	cmdLogin.Flag("client-id", "OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)").Envar("ONELOGIN_CLIENT_ID").StringVar(&commonFlags.ClientID)
	cmdLogin.Flag("client-secret", "OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)").Envar("ONELOGIN_CLIENT_SECRET").StringVar(&commonFlags.ClientSecret)
	cmdLogin.Flag("force", "Refresh credentials even if not expired.").BoolVar(&loginFlags.Force)
	cmdLogin.Flag("credential-process", "Enables AWS Credential Process support by outputting credentials to STDOUT in a JSON message.").BoolVar(&loginFlags.CredentialProcess)
	cmdLogin.Flag("credentials-file", "The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)").Envar("SAML2AWS_CREDENTIALS_FILE").StringVar(&commonFlags.CredentialsFile)

	// `exec` command and settings
	cmdExec := app.Command("exec", "Exec the supplied command with env vars from STS token.")
	execFlags := new(flags.LoginExecFlags)
	execFlags.CommonFlags = commonFlags
	cmdExec.Flag("profile", "The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)").Envar("SAML2AWS_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdExec.Flag("exec-profile", "The AWS profile to utilize for command execution. Useful to allow the aws cli to perform secondary role assumption. (env: SAML2AWS_EXEC_PROFILE)").Envar("SAML2AWS_EXEC_PROFILE").StringVar(&execFlags.ExecProfile)
	cmdExec.Flag("credentials-file", "The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)").Envar("SAML2AWS_CREDENTIALS_FILE").StringVar(&commonFlags.CredentialsFile)
	cmdLine := buildCmdList(cmdExec.Arg("command", "The command to execute."))

	// `console` command and settings
	cmdConsole := app.Command("console", "Console will open the aws console after logging in.")
	consoleFlags := new(flags.ConsoleFlags)
	consoleFlags.LoginExecFlags = execFlags
	consoleFlags.LoginExecFlags.CommonFlags = commonFlags
	cmdConsole.Flag("exec-profile", "The AWS profile to utilize for console execution. (env: SAML2AWS_EXEC_PROFILE)").Envar("SAML2AWS_EXEC_PROFILE").StringVar(&consoleFlags.LoginExecFlags.ExecProfile)
	cmdConsole.Flag("profile", "The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)").Envar("SAML2AWS_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdConsole.Flag("force", "Refresh credentials even if not expired.").BoolVar(&consoleFlags.LoginExecFlags.Force)
	cmdConsole.Flag("link", "Present link to AWS console instead of opening browser").BoolVar(&consoleFlags.Link)
	cmdConsole.Flag("credentials-file", "The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)").Envar("SAML2AWS_CREDENTIALS_FILE").StringVar(&commonFlags.CredentialsFile)

	// `list` command and settings
	cmdListRoles := app.Command("list-roles", "List available role ARNs.")
	listRolesFlags := new(flags.LoginExecFlags)
	listRolesFlags.CommonFlags = commonFlags

	// `script` command and settings
	cmdScript := app.Command("script", "Emit a script that will export environment variables.")
	scriptFlags := new(flags.LoginExecFlags)
	scriptFlags.CommonFlags = commonFlags
	cmdScript.Flag("profile", "The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)").Envar("SAML2AWS_PROFILE").Short('p').StringVar(&commonFlags.Profile)
	cmdScript.Flag("credentials-file", "The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)").Envar("SAML2AWS_CREDENTIALS_FILE").StringVar(&commonFlags.CredentialsFile)
	var shell string
	cmdScript.
		Flag("shell", "Type of shell environment. Options include: bash, powershell, fish").
		Default("bash").
		EnumVar(&shell, "bash", "powershell", "fish")

	// Trigger the parsing of the command line inputs via kingpin
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// will leave this here for a while during upgrade process
	if *provider != "" {
		log.Println("The --provider flag has been replaced with a new configure command. See https://github.com/versent/saml2aws/v2#adding-idp-accounts")
		os.Exit(1)
	}

	errtpl := "%v\n"
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
		errtpl = "%+v\n"
	}

	if *quiet {
		log.SetOutput(ioutil.Discard)
		logrus.SetOutput(ioutil.Discard)
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
		log.Printf(errtpl, err)
		os.Exit(1)
	}
}
