package flags

import (
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

// CommonFlags flags common to all of the `saml2aws` commands (except `help`)
type CommonFlags struct {
	AppID                string
	ClientID             string
	ClientSecret         string
	ConfigFile           string
	IdpAccount           string
	IdpProvider          string
	MFA                  string
	MFAToken             string
	URL                  string
	Username             string
	Password             string
	RoleArn              string
	AmazonWebservicesURN string
	SessionDuration      int
	SkipPrompt           bool
	SkipVerify           bool
	Profile              string
	Subdomain            string
	ResourceID           string
	DisableKeychain      bool
	Region               string
	CredentialsFile      string
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags       *CommonFlags
	Force             bool
	DuoMFAOption      string
	ExecProfile       string
	CredentialProcess bool
}

type ConsoleFlags struct {
	LoginExecFlags *LoginExecFlags
	Link           bool
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

	if commonFlags.MFA != "" {
		account.MFA = commonFlags.MFA
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
	if commonFlags.ResourceID != "" {
		account.ResourceID = commonFlags.ResourceID
	}
	if commonFlags.Region != "" {
		account.Region = commonFlags.Region
	}
	if commonFlags.CredentialsFile != "" {
		account.CredentialsFile = commonFlags.CredentialsFile
	}
}
