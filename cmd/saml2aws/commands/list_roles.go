package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/samlcache"
)

// ListRoles will list available role ARNs
func ListRoles(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "list")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	// creates a cacheProvider, only used when --cache is set
	cacheProvider := &samlcache.SAMLCacheProvider{
		Account:  account.Name,
		Filename: account.SAMLCacheFile,
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	provider, err := saml2aws.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	err = provider.Validate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	var samlAssertion string
	if account.SAMLCache {
		if cacheProvider.IsValid() {
			samlAssertion, err = cacheProvider.Read()
			if err != nil {
				logger.Debug("Could not read cache:", err)
			}
		}
	}

	if samlAssertion == "" {
		// samlAssertion was not cached
		samlAssertion, err = provider.Authenticate(loginDetails)
		if err != nil {
			return errors.Wrap(err, "error authenticating to IdP")
		}
		if account.SAMLCache {
			err = cacheProvider.Write(samlAssertion)
			if err != nil {
				logger.Error("Could not write samlAssertion:", err)
			}
		}
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
		fmt.Println(account.Name)
		for _, role := range account.Roles {
			fmt.Println(role.RoleARN)
		}
		fmt.Println("")
	}

	return nil
}
