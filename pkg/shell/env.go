package shell

import (
	"fmt"
	"time"

	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
)

// BuildEnvVars build an array of env vars in the format required for exec
func BuildEnvVars(awsCreds *awsconfig.AWSCredentials) []string {

	environmentVars := []string{
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", awsCreds.AWSSessionToken),
		fmt.Sprintf("AWS_SECURITY_TOKEN=%s", awsCreds.AWSSecurityToken),
		fmt.Sprintf("EC2_SECURITY_TOKEN=%s", awsCreds.AWSSecurityToken),
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", awsCreds.AWSAccessKey),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", awsCreds.AWSSecretKey),
		fmt.Sprintf("AWS_CREDENTIAL_EXPIRATION=%s", awsCreds.Expires.Format(time.RFC3339)),
	}

	return environmentVars
}
