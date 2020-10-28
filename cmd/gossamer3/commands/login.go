package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile)

	logger.Debug("check if Creds Exist")

	// this checks if the credentials file has been created yet
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	if !sharedCreds.Expired() && !loginFlags.Force {
		log.Println("Credentials are not expired (use --force to login anyways)")
		return nil
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

	log.Printf("Authenticating as %s ...", loginDetails.Username)

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

	role, err := selectAwsRole(samlAssertion, account)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role, please check whether you are permitted to assume the given role for the AWS service")
	}

	log.Println("Selected role:", role.RoleARN)

	awsCreds, err := loginToStsUsingRole(role, account.SessionDuration, samlAssertion, account.Region)
	if err != nil {
		return errors.Wrap(err, "error logging into aws role using saml assertion")
	}

	// Assume a child role
	if loginFlags.AssumeChildRole != "" {
		samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
		if err != nil {
			return errors.Wrap(err, "error decoding saml assertion")
		}

		// Get the role session name to use in role assumptions
		roleSessionName, err := g3.ExtractRoleSessionName(samlAssertionData)
		if err != nil {
			return errors.Wrap(err, "error extracting role session name")
		}
		roleSessionName = fmt.Sprintf("gossamer3-%s", roleSessionName)

		// Assume child role
		awsCreds, err = assumeRole(awsCreds, loginFlags.AssumeChildRole, roleSessionName, account.Region)
		if err != nil {
			return errors.Wrap(err, "error assuming child role")
		}
	}

	return saveCredentials(awsCreds, sharedCreds)
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(loginFlags.CommonFlags.ConfigFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load idp account")
	} else if account == nil {
		return nil, errors.Errorf("idp account %s does not exist", loginFlags.CommonFlags.IdpAccount)
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

	// log.Printf("loginFlags %+v", loginFlags)

	loginDetails := &creds.LoginDetails{
		URL:       account.URL,
		Username:  account.Username,
		MFAToken:  loginFlags.CommonFlags.MFAToken,
		MFADevice: account.MFADevice,
		MFAPrompt: account.MFAPrompt,
	}

	log.Printf("Using IDP Account %s to access %s %s", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	var err error
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.LookupCredentials(loginDetails, account.Provider)
		if err != nil {
			if !credentials.IsErrCredentialsNotFound(err) {
				return nil, errors.Wrap(err, "error loading saved password")
			}
		}
	}

	// log.Printf("%s %s", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	if loginFlags.CommonFlags.Password != "" {
		loginDetails.Password = loginFlags.CommonFlags.Password
	}

	if loginFlags.CommonFlags.MFADevice != "" {
		loginDetails.MFADevice = loginFlags.CommonFlags.MFADevice
	}

	// log.Printf("loginDetails %+v", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt {
		return loginDetails, nil
	}

	err = g3.PromptForLoginDetails(loginDetails, account.Provider)
	if err != nil {
		return nil, errors.Wrap(err, "Error occurred accepting input")
	}

	return loginDetails, nil
}

func grabAllAwsRoles(samlAssertion []byte) ([]*g3.AWSRole, error) {
	roles, err := g3.ExtractAwsRoles(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	if len(roles) == 0 {
		log.Println("No roles to assume")
		log.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	return g3.ParseAWSRoles(roles)
}

func selectAwsRole(samlAssertion string, account *cfg.IDPAccount) (*g3.AWSRole, error) {
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	awsRoles, err := grabAllAwsRoles(data)
	if err != nil {
		return nil, err
	}

	return resolveRole(awsRoles, samlAssertion, account)
}

func resolveRole(awsRoles []*g3.AWSRole, samlAssertion string, account *cfg.IDPAccount) (*g3.AWSRole, error) {
	var role = new(g3.AWSRole)

	if len(awsRoles) == 1 {
		if account.RoleARN != "" {
			return g3.LocateRole(awsRoles, account.RoleARN)
		}
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("no roles available")
	}

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	aud, err := g3.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing destination url")
	}

	awsAccounts, err := g3.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws role accounts")
	}
	if len(awsAccounts) == 0 {
		return nil, errors.New("no accounts available")
	}

	g3.AssignPrincipals(awsRoles, awsAccounts)

	if account.RoleARN != "" {
		return g3.LocateRole(awsRoles, account.RoleARN)
	}

	for {
		role, err = g3.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		log.Println("error selecting role, try again")
	}

	return role, nil
}

func loginToStsUsingRole(role *g3.AWSRole, sessionDuration int, samlAssertion, region string) (*awsconfig.AWSCredentials, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	// Set user agent handler
	awsconfig.OverrideUserAgent(sess)

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(int64(sessionDuration)),
	}

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving STS credentials using SAML")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           region,
	}, nil
}

func saveCredentials(awsCreds *awsconfig.AWSCredentials, sharedCreds *awsconfig.CredentialsProvider) error {
	err := sharedCreds.Save(awsCreds)
	if err != nil {
		return errors.Wrap(err, "error saving credentials")
	}

	log.Println("Logged in as:", awsCreds.PrincipalARN)
	log.Println("")
	log.Println("Your new access key pair has been stored in the AWS configuration")
	log.Printf("Note that it will expire at %v", awsCreds.Expires)
	log.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", sharedCreds.Profile, "ec2 describe-instances).")

	return nil
}
