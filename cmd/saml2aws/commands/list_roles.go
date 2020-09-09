package commands

import (
	b64 "encoding/base64"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/flags"
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

	provider, err := saml2aws.NewSAMLClient(account)
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
		log.Println("To see the output follow the instructions in https://github.com/versent/saml2aws#debugging-issues-with-idps")
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

	roles, err := saml2aws.ExtractAwsRoles(data)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	if len(roles) == 0 {
		log.Println("No roles to assume")
		os.Exit(1)
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	if err := listRoles(awsRoles, samlAssertion, loginFlags); err != nil {
		return errors.Wrap(err, "Failed to list roles")
	}

	return nil
}

func listRoles(awsRoles []*saml2aws.AWSRole, samlAssertion string, loginFlags *flags.LoginExecFlags) error {
	if len(awsRoles) == 1 {
		log.Println("")
		log.Println("Only one role to assume. Will be automatically assumed on login")
		log.Println(awsRoles[0].RoleARN)
		return nil
	} else if len(awsRoles) == 0 {
		return errors.New("no roles available")
	}

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error decoding saml assertion")
	}

	aud, err := saml2aws.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return errors.Wrap(err, "error parsing destination url")
	}

	awsAccounts, err := saml2aws.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error parsing aws role accounts")
	}

	saml2aws.AssignPrincipals(awsRoles, awsAccounts)

	log.Println("")
	for _, account := range awsAccounts {
		log.Println(account.Name)
		for _, role := range account.Roles {
			log.Println(role.RoleARN)
		}
		log.Println("")
	}

	return nil
}
