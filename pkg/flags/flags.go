package flags

import (
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

// CommonFlags flags common to all of the `saml2aws` commands (except `help`)
type CommonFlags struct {
	AppID                 string `help:"OneLogin app id required for SAML assertion" env:"ONELOGIN_APP_ID" optional:""`
	ClientID              string `help:"OneLogin client id, used to generate API access token" env:"ONELOGIN_CLIENT_ID" optional:""`
	ClientSecret          string `help:"OneLogin client secret, used to generate API access token" env:"ONELOGIN_CLIENT_SECRET" optional:""`
    ConfigFile            string `help:"Path/filename of saml2aws config file" env:"SAML2AWS_CONFIGFILE optional:""`
	IdpAccount            string `help:"The name of the configured IDP account" env:"SAML2AWS_IDP_ACCOUNT" default:"default"`
	IdpProvider           string `help:"The configured IDP provider" env:"SAML2AWS_IDP_PROVIDER" enum:"Akamai,AzureAD,ADFS,ADFS2,Browser,Ping,JumpCloud,Okta,OneLogin,PSU,KeyCloak," optional:""`
	BrowserType           string `help:"The configured browser type when the IDP provider is set to Browser" env:"SAML2AWS_BROWSER_TYPE" enum:"chromium,firefox,webkit,chrome,chrome-beta,chrome-dev,chrome-canary,msedge,msedge-beta,msedge-dev,msedge-canary" optional:""`
	BrowserExecutablePath string `help:"The configured browser full path when the IDP provider is set to Browser" env:"SAML2AWS_BROWSER_EXECUTABLE_PATH" optional:""`
	BrowserAutoFill       bool   `help:"Configures browser to autofill the username and password" env:"SAML2AWS_BROWSER_AUTOFILL" optional:""`
	MFA                   string `help:"The name of the mfa" env:"SAML2AWS_MFA" optional:""`
	SkipVerify            bool   `help:"Skip verification of server certificate" env:"SAML2AWS_SKIP_VERIFY" optional:""`
	URL                   string `help:"The URL of the SAML IDP server used to login" env:"SAML2AWS_URL" optional:""`
	Username              string `help:"The username used to login" env:"SAML2AWS_USERNAME" optional:""`
	Password              string `help:"The password used to login" env:"SAML2AWS_PASSWORD" optional:""`
	MFAToken              string `help:"The current MFA token" env:"SAML2AWS_MFA_TOKEN" optional:""`
	RoleArn               string `help:"The ARN of the role to assume" env:"SAML2AWS_ROLE" optional:""`
	PolicyFile            string `help:"The file containing the supplemental AssumeRole policy" env:"SAML2AWS_POLICY_FILE" optional:""`
	PolicyARNs            string `help:"The ARN of supplemental policies to restrict the token" env:"SAML2AWS_POLICY_ARNS" optional:""`
	AmazonWebservicesURN  string `help:"The URN used by SAML when you login" env:"SAML2AWS_AWS_URN" optional:""`
	SkipPrompt            bool   `help:"Skip prompting for parameters during login" optional:""`
	SessionDuration       int    `help:"The duration of your AWS Session" env:"SAML2AWS_SESSION_DURATION" optional:""`
	DisableKeychain       bool   `help:"Do not use keychain at all" env:"SAML2AWS_DISABLE_KEYCHAIN" optional:""`
	Subdomain             string `help:"OneLogin subdomain of your company account" env:"ONELOGIN_SUBDOMAIN" optional:""`
	Profile               string `help:"The AWS profile to save the temporary credentials" env:"SAML2AWS_PROFILE" optional:""`
	ResourceID            string `help:"F5APM SAML resource ID of your company account" env:"SAML2AWS_F5APM_RESOURCE_ID" optional:""`
	CredentialsFile       string `help:"The file that will cache the credentials retrieved from AWS" env:"SAML2AWS_CREDENTIALS_FILE" optional:""`
	SAMLCache             bool   `help:"Caches the SAML response" env:"SAML2AWS_CACHE_SAML" optional:""`
	SAMLCacheFile         string `help:"The location of the SAML cache file" env:"SAML2AWS_SAML_CACHE_FILE" optional:""`
	DisableSessions       bool   `help:"Do not use Okta sessions" env:"SAML2AWS_OKTA_DISABLE_SESSIONS" optional:""`
	DisableRememberDevice bool   `help:"Do not remember Okta MFA device. Remembers MFA device by default." env:"SAML2AWS_OKTA_DISABLE_REMEMBER_DEVICE" optional:""`
	MFAIPAddress          string `help:"IP address whitelisting defined in OneLogin MFA policies" env:"ONELOGIN_MFA_IP_ADDRESS" optional:""`
    Region                string `help:"AWS region to use for API requests" env:"SAML2AWS_REGION" optional:""`
	Prompter              string `help:"The prompter to use for user input"`
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags       *CommonFlags
	DownloadBrowser   bool   `help:"Automatically download browsers for Browser IDP" env:"SAML2AWS_AUTO_BROWSER_DOWNLOAD" optional:""`
	Force             bool   `help:"Refresh credentials even if not expired" optional:""`
	DuoMFAOption      string `help:"The MFA option you want to use to authenticate with" env:"SAML2AWS_DUO_MFA_OPTION" enum:"Passcode,Duo Push," default:""`
	ExecProfile       string `help:"The AWS profile to utilize for command execution" env:"SAML2AWS_EXEC_PROFILE" optional:""`
	CredentialProcess bool   `help:"Enables AWS Credential Process support by outputting credentials to STDOUT in a JSON message" optional:""`
}

type ConsoleFlags struct {
	LoginExecFlags *LoginExecFlags
	Link           bool   `help:"Present link to AWS console instead of opening browser" optional:""`
}

// ApplyFlagOverrides overrides IDPAccount with command line settings
func ApplyFlagOverrides(commonFlags *CommonFlags, account *cfg.IDPAccount) {
	if commonFlags.AppID != "" {
		account.AppID = commonFlags.AppID
	}

	if commonFlags.URL != "" {
		account.URL = commonFlags.URL
	}

	if commonFlags.Username != "" {
		account.Username = commonFlags.Username
	}

	if commonFlags.SkipVerify {
		account.SkipVerify = commonFlags.SkipVerify
	}

	if commonFlags.IdpProvider != "" {
		account.Provider = commonFlags.IdpProvider
	}

	if commonFlags.BrowserType != "" {
		account.BrowserType = commonFlags.BrowserType
	}

	if commonFlags.BrowserExecutablePath != "" {
		account.BrowserExecutablePath = commonFlags.BrowserExecutablePath
	}

	if commonFlags.BrowserAutoFill {
		account.BrowserAutoFill = commonFlags.BrowserAutoFill
	}

	if commonFlags.MFA != "" {
		account.MFA = commonFlags.MFA
	}

	if commonFlags.MFAIPAddress != "" {
		account.MFAIPAddress = commonFlags.MFAIPAddress
	}

	if commonFlags.AmazonWebservicesURN != "" {
		account.AmazonWebservicesURN = commonFlags.AmazonWebservicesURN
	}

	if commonFlags.SessionDuration != 0 {
		account.SessionDuration = commonFlags.SessionDuration
	}

	if commonFlags.Profile != "" {
		account.Profile = commonFlags.Profile
	}

	if commonFlags.Subdomain != "" {
		account.Subdomain = commonFlags.Subdomain
	}

	if commonFlags.RoleArn != "" {
		account.RoleARN = commonFlags.RoleArn
	}
	if commonFlags.PolicyFile != "" {
		account.PolicyFile = commonFlags.PolicyFile
	}
	if commonFlags.PolicyARNs != "" {
		account.PolicyARNs = commonFlags.PolicyARNs
	}
	if commonFlags.ResourceID != "" {
		account.ResourceID = commonFlags.ResourceID
	}
	if commonFlags.Region != "" {
		account.Region = commonFlags.Region
	}
	if commonFlags.CredentialsFile != "" {
		account.CredentialsFile = commonFlags.CredentialsFile
	}
	if commonFlags.SAMLCache {
		account.SAMLCache = commonFlags.SAMLCache
	}
	if commonFlags.SAMLCacheFile != "" {
		account.SAMLCacheFile = commonFlags.SAMLCacheFile
	}
	if commonFlags.DisableRememberDevice {
		account.DisableRememberDevice = commonFlags.DisableRememberDevice
	}
	if commonFlags.DisableSessions {
		account.DisableSessions = commonFlags.DisableSessions
	}
	if commonFlags.Prompter != "" {
		account.Prompter = commonFlags.Prompter
	}

	// select the prompter
	if commonFlags.Prompter != "" {
		account.Prompter = commonFlags.Prompter
	}
}
