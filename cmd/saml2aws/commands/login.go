package commands

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/flags"
	"github.com/versent/saml2aws/pkg/shell"
)

// MaxDurationSeconds the maximum duration in seconds for an STS session
const MaxDurationSeconds = 3600

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authenticating as %s ...\n", loginDetails.Username)

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
		fmt.Println("Response did not contain a valid SAML assertion")
		fmt.Println("Please check your username and password is correct")
		os.Exit(1)
	}

	err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
	if err != nil {
		return errors.Wrap(err, "error storing password in keychain")
	}

	data, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error decoding saml assertion")
	}

	roles, err := saml2aws.ExtractAwsRoles(data)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	if len(roles) == 0 {
		fmt.Println("No roles to assume")
		fmt.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return errors.Wrap(err, "error parsing aws roles")
	}

	role, err := resolveRole(awsRoles, samlAssertion, loginFlags)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role, please check you are permitted to assume the given role for the AWS service")
	}

	fmt.Println("Selected role:", role.RoleARN)

	err = loginToStsUsingRole(role, samlAssertion, loginFlags.Profile)
	if err != nil {
		return errors.Wrap(err, "error logging into aws role using saml assertion")
	}

	sharedCreds := awsconfig.NewSharedCredentials(loginFlags.Profile)

	// if export vars is enabled.
	id, secret, token, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	envVars := shell.BuildEnvVarsMap(id, secret, token)

	for k, v := range envVars {
		os.Setenv(k, v)
	}

	return nil
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(cfg.DefaultConfigPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadVerifyIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		if cfg.IsErrIdpAccountNotFound(err) {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		return nil, errors.Wrap(err, "failed to load idp account")
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(loginFlags.CommonFlags, account)

	err = account.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to validate account")
	}

	return account, nil
}

func resolveLoginDetails(account *cfg.IDPAccount, loginFlags *flags.LoginExecFlags) (*creds.LoginDetails, error) {

	// fmt.Printf("loginFlags %+v\n", loginFlags)

	loginDetails := &creds.LoginDetails{URL: account.URL, Username: account.Username}

	fmt.Printf("Using IDP Account %s to access %s %s\n", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	err := credentials.LookupCredentials(loginDetails)
	if err != nil {
		if !credentials.IsErrCredentialsNotFound(err) {
			return nil, errors.Wrap(err, "error loading saved password")
		}
	}

	// fmt.Printf("%s %s\n", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	// if you supply a password in a flag it takes precedence
	if loginFlags.Password != "" {
		loginDetails.Password = loginFlags.Password
	}

	// fmt.Printf("loginDetails %+v\n", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt {
		return loginDetails, nil
	}

	err = saml2aws.PromptForLoginDetails(loginDetails)
	if err != nil {
		return nil, errors.Wrap(err, "Error occurred accepting input")
	}

	return loginDetails, nil
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion string, loginFlags *flags.LoginExecFlags) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		if loginFlags.CommonFlags.RoleSupplied() {
			return saml2aws.LocateRole(awsRoles, loginFlags.CommonFlags.RoleArn)
		}
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("no roles available")
	}

	awsAccounts, err := saml2aws.ParseAWSAccounts(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws role accounts")
	}

	saml2aws.AssignPrincipals(awsRoles, awsAccounts)

	if loginFlags.CommonFlags.RoleSupplied() {
		return saml2aws.LocateRole(awsRoles, loginFlags.CommonFlags.RoleArn)
	}

	for {
		role, err = saml2aws.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		fmt.Println("error selecting role, try again")
	}

	return role, nil
}

func loginToStsUsingRole(role *saml2aws.AWSRole, samlAssertion string, profile string) error {

	sess, err := session.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(MaxDurationSeconds), // 1 hour
	}

	fmt.Println("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return errors.Wrap(err, "error retrieving STS credentials using SAML")
	}

	// fmt.Println("Saving credentials")

	sharedCreds := awsconfig.NewSharedCredentials(profile)

	err = sharedCreds.Save(aws.StringValue(resp.Credentials.AccessKeyId), aws.StringValue(resp.Credentials.SecretAccessKey), aws.StringValue(resp.Credentials.SessionToken))
	if err != nil {
		return errors.Wrap(err, "error saving credentials")
	}

	fmt.Println("Logged in as:", aws.StringValue(resp.AssumedRoleUser.Arn))
	fmt.Println("")
	fmt.Println("Your new access key pair has been stored in the AWS configuration")
	fmt.Printf("Note that it will expire at %v\n", resp.Credentials.Expiration.Local())
	fmt.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", profile, "ec2 describe-instances).")

	return nil
}
