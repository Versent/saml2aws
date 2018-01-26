package shell

import "fmt"

// BuildEnvVars build an array of env vars in the format required for exec
func BuildEnvVars(id, secret, token string) []string {
	return []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", id),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", secret),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", token),
		fmt.Sprintf("AWS_SECURITY_TOKEN=%s", token),
		fmt.Sprintf("EC2_SECURITY_TOKEN=%s", token),
	}
}

// BuildEnvVarsMap build a map of env vars
func BuildEnvVarsMap(id, secret, token string) map[string]string {

	envVars := make(map[string]string)

	envVars["AWS_ACCESS_KEY_ID"] = id
	envVars["AWS_SECRET_ACCESS_KEY"] = secret
	envVars["AWS_SESSION_TOKEN"] = token
	envVars["AWS_SECURITY_TOKEN"] = token
	envVars["EC2_SECURITY_TOKEN"] = token

	return envVars
}
