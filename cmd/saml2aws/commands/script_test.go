package commands

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
)

func TestBuildTmplBash(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("bash", data)
	assert.ErrorIs(t, err, nil)

	expected := []string{
		"export AWS_ACCESS_KEY_ID=\"access_key\"",
		"export AWS_SECRET_ACCESS_KEY=\"secret_key\"",
		"export AWS_SESSION_TOKEN=\"session_token\"",
		"export AWS_SECURITY_TOKEN=\"security_token\"",
		"export SAML2AWS_PROFILE=\"test_profile\"",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplFish(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("fish", data)
	assert.ErrorIs(t, err, nil)

	expected := []string{
		"set -gx AWS_ACCESS_KEY_ID access_key",
		"set -gx AWS_SECRET_ACCESS_KEY secret_key",
		"set -gx AWS_SESSION_TOKEN session_token",
		"set -gx AWS_SECURITY_TOKEN security_token",
		"set -gx SAML2AWS_PROFILE test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}

func TestBuildTmplEnv(t *testing.T) {

	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		"test_profile",
		&awsconfig.AWSCredentials{
			AWSSecretKey:     "secret_key",
			AWSAccessKey:     "access_key",
			AWSSessionToken:  "session_token",
			AWSSecurityToken: "security_token",
			Expires:          time.Now(),
		},
	}

	st, err := buildTmpl("env", data)
	assert.ErrorIs(t, err, nil)

	expected := []string{
		"AWS_ACCESS_KEY_ID=access_key",
		"AWS_SECRET_ACCESS_KEY=secret_key",
		"AWS_SESSION_TOKEN=session_token",
		"AWS_SECURITY_TOKEN=security_token",
		"SAML2AWS_PROFILE=test_profile",
	}

	for _, test_string := range expected {
		assert.Contains(t, st, test_string)
	}

}
