package shell

import (
	"fmt"
	"github.com/versent/saml2aws/pkg/flags"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
)

// BuildEnvVars build an array of env vars in the format required for exec
func BuildEnvVars(awsCreds *awsconfig.AWSCredentials, account *cfg.IDPAccount, execFlags *flags.LoginExecFlags) []string {

	environmentVars := []string  {
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", awsCreds.AWSSessionToken),
		fmt.Sprintf("AWS_SECURITY_TOKEN=%s", awsCreds.AWSSecurityToken),
		fmt.Sprintf("EC2_SECURITY_TOKEN=%s", awsCreds.AWSSecurityToken),
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", awsCreds.AWSAccessKey),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", awsCreds.AWSSecretKey),
	}

	if execFlags.ExecProfile == "" {
		// Only set profile env vars if we haven't already assumed a role via a profile
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_PROFILE=%s", account.Profile))
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_DEFAULT_PROFILE=%s", account.Profile))
	}
	return environmentVars
}
