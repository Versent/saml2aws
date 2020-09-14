package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ListRoles will list available role ARNs
func ListRoles(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "list")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	err = loginDetails.Validate()
	if err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	provider, err := g3.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error authenticating to IdP")

	}

	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion")
		log.Println("Please check your username and password is correct")
		log.Println("To see the output follow the instructions in https://github.com/GESkunkworks/gossamer3#debugging-issues-with-idps")
		os.Exit(1)
	}

	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	}

	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error decoding saml assertion")
	}

	roles, err := g3.ExtractAwsRoles(data)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	if len(roles) == 0 {
		fmt.Println("No roles to assume")
		os.Exit(1)
	}

	awsRoles, err := g3.ParseAWSRoles(roles)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	if err := listRoles(awsRoles, samlAssertion, loginFlags); err != nil {
		return errors.Wrap(err, "Failed to list roles")
	}

	return nil
}

func listRoles(awsRoles []*g3.AWSRole, samlAssertion string, loginFlags *flags.LoginExecFlags) error {
	if len(awsRoles) == 1 {
		fmt.Println("")
		fmt.Println("Only one role to assume. Will be automatically assumed on login")
		fmt.Println(awsRoles[0].RoleARN)
		return nil
	} else if len(awsRoles) == 0 {
		return errors.New("no roles available")
	}

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error decoding saml assertion")
	}

	aud, err := g3.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return errors.Wrap(err, "error parsing destination url")
	}

	awsAccounts, err := g3.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error parsing aws role accounts")
	}

	g3.AssignPrincipals(awsRoles, awsAccounts)

	fmt.Println("")
	for _, account := range awsAccounts {
		fmt.Println(account.Name)
		for _, role := range account.Roles {
			fmt.Println(role.RoleARN)
		}
		fmt.Println("")
	}

	return nil
}
