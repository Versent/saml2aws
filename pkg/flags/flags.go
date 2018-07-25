package flags

import (
	"github.com/versent/saml2aws/pkg/cfg"
)

// CommonFlags flags common to all of the `saml2aws` commands (except `help`)
type CommonFlags struct {
	AppID                string
	ClientID             string
	ClientSecret         string
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
}

// RoleSupplied role arn has been passed as a flag
func (cf *CommonFlags) RoleSupplied() bool {
	return cf.RoleArn != ""
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags *CommonFlags
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
}
