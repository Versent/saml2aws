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
	}

	//To run exec with a non default (saml) profile 'AWS_ACCESS_KEY_ID' and 'AWS_SECRET_ACCESS_KEY' must not be set
	if execFlags.ExecProfile == "" {
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", awsCreds.AWSAccessKey))
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", awsCreds.AWSSecretKey))
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_PROFILE=%s", account.Profile))
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_DEFAULT_PROFILE=%s", account.Profile))
	} else {
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_PROFILE=%s", execFlags.ExecProfile))
		environmentVars = append(environmentVars, fmt.Sprintf("AWS_DEFAULT_PROFILE=%s", execFlags.ExecProfile))
	}
	return environmentVars
}
