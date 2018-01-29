package flags

import "github.com/versent/saml2aws/pkg/cfg"

// CommonFlags flags common to all of the `saml2aws` commands (except `help`)
type CommonFlags struct {
	IdpAccount           string
	IdpProvider          string
	MFA                  string
	URL                  string
	Username             string
	Password             string
	RoleArn              string
	AmazonWebservicesURN string
	SkipPrompt           bool
	SkipVerify           bool
}

// RoleSupplied role arn has been passed as a flag
func (cf *CommonFlags) RoleSupplied() bool {
	return cf.RoleArn != ""
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags *CommonFlags
	Profile     string
}

// ApplyFlagOverrides overrides IDPAccount with command line settings
func ApplyFlagOverrides(commonFlags *CommonFlags, account *cfg.IDPAccount) {
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
}
