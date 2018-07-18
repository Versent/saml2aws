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

	ok, err := checkToken(account.Profile)
	if err != nil {
		return errors.Wrap(err, "error validating token")
	}

	if !ok {
		err = Login(execFlags)
	}
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	err = buildTmpl(shell, awsCreds)
	if err != nil {
		return errors.Wrap(err, "error generating template")
	}

	return nil
}

func buildTmpl(shell string, creds *awsconfig.AWSCredentials) error {
	var tmplFile string
	switch shell {
	case "bash":
		tmplFile = "templates/bash.gotemplate"
	case "powershell":
		tmplFile = "templates/powershell.gotemplate"
	case "fish":
		tmplFile = "templates/fish.gotemplate"
	}

	t, err := template.ParseFiles(tmplFile)
	if err != nil {
		return err
	}

	return t.Execute(os.Stdout, creds)
}
