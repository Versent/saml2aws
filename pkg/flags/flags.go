package flags

import (
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
)

// CommonFlags flags common to all of the `gossamer3` commands (except `help`)
type CommonFlags struct {
	ConfigFile           string
	IdpAccount           string
	IdpProvider          string
	MFA                  string
	MFAToken             string
	MFADevice            string
	URL                  string
	Username             string
	Password             string
	RoleArn              string
	AmazonWebservicesURN string
	SessionDuration      int
	SkipPrompt           bool
	SkipVerify           bool
	Profile              string
	DisableKeychain      bool
	Quiet                bool
	Region               string
}

// LoginExecFlags flags for the Login / Exec commands
type LoginExecFlags struct {
	CommonFlags     *CommonFlags
	Force           bool
	ExecProfile     string
	AssumeChildRole string
	BulkLoginConfig string
}

type ConsoleFlags struct {
	LoginExecFlags *LoginExecFlags
	Link           bool
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

	if commonFlags.SessionDuration != 0 {
		account.SessionDuration = commonFlags.SessionDuration
	}

	if commonFlags.Profile != "" {
		account.Profile = commonFlags.Profile
	}

	if commonFlags.RoleArn != "" {
		account.RoleARN = commonFlags.RoleArn
	}
	if commonFlags.Region != "" {
		account.Region = commonFlags.Region
	}
}
