package commands

import (
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/flags"
)

const bashTmpl = `export AWS_ACCESS_KEY_ID="{{ .AWSAccessKey }}"
export AWS_SECRET_ACCESS_KEY="{{ .AWSSecretKey }}"
export AWS_SESSION_TOKEN="{{ .AWSSessionToken }}"
export AWS_SECURITY_TOKEN="{{ .AWSSecurityToken }}"
export SAML2AWS_PROFILE="{{ .ProfileName }}"
`

const fishTmpl = `set -gx AWS_ACCESS_KEY_ID {{ .AWSAccessKey }}
set -gx AWS_SECRET_ACCESS_KEY {{ .AWSSecretKey }}
set -gx AWS_SESSION_TOKEN {{ .AWSSessionToken }}
set -gx AWS_SECURITY_TOKEN {{ .AWSSecurityToken }}
set -gx SAML2AWS_PROFILE {{ .ProfileName }}
"
`

const powershellTmpl = `$env:AWS_ACCESS_KEY_ID='{{ .AWSAccessKey }}'
$env:AWS_SECRET_ACCESS_KEY='{{ .AWSSecretKey }}'
$env:AWS_SESSION_TOKEN='{{ .AWSSessionToken }}'
$env:AWS_SECURITY_TOKEN='{{ .AWSSecurityToken }}'
$env:SAML2AWS_PROFILE='{{ .ProfileName }}'
`

// Script will emit a bash script that will export environment variables
func Script(execFlags *flags.LoginExecFlags, shell string) error {
	account, err := buildIdpAccount(execFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2aws exec is run on a new
	// system prior to creating $HOME/.aws
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		fmt.Println("unable to load credentials, login required to create them")
		return nil
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	if awsCreds.Expires.Sub(time.Now()) < 0 {
		return errors.New("error aws credentials have expired")
	}

	// annoymous struct to pass to template
	data := struct {
		ProfileName string
		*awsconfig.AWSCredentials
	}{
		account.Profile,
		awsCreds,
	}

	err = buildTmpl(shell, data)
	if err != nil {
		return errors.Wrap(err, "error generating template")
	}

	return nil
}

func buildTmpl(shell string, data interface{}) error {
	t := template.New("envvar_script")

	var err error

	switch shell {
	case "bash":
		t, err = t.Parse(bashTmpl)
	case "powershell":
		t, err = t.Parse(powershellTmpl)
	case "fish":
		t, err = t.Parse(fishTmpl)
	}

	if err != nil {
		return err
	}

	return t.Execute(os.Stdout, data)
}
