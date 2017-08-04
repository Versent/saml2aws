package commands

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/helper/credentials"
)

// LoginFlags login specific command flags
type LoginFlags struct {
	Provider   string
	Profile    string
	Hostname   string
	Username   string
	Password   string
	RoleArn    string
	SkipVerify bool
	SkipPrompt bool
}

// RoleSupplied role arn has been passed as a flag
func (lf *LoginFlags) RoleSupplied() bool {
	return lf.RoleArn != ""
}

// Login login to ADFS
func Login(loginFlags *LoginFlags) error {

	config := saml2aws.NewConfigLoader(loginFlags.Provider)

	hostname, err := config.LoadHostname()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	// fmt.Println("LookupCredentials", hostname)

	loginDetails, err := resolveLoginDetails(hostname, loginFlags)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authenticating as %s to %s https://%s\n", loginDetails.Username, loginFlags.Provider, loginDetails.Hostname)

	opts := &saml2aws.SAMLOptions{Provider: loginFlags.Provider, SkipVerify: loginFlags.SkipVerify}

	provider, err := saml2aws.NewSAMLClient(opts)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	err = loginDetails.Validate()
	if err != nil {
		return errors.Wrap(err, "error validating login details")
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

	err = credentials.SaveCredentials(loginDetails.Hostname, loginDetails.Username, loginDetails.Password)
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

	sess, err := session.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(3600),               // 1 hour
	}

	fmt.Println("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return errors.Wrap(err, "error retrieving STS credentials using SAML")
	}

	// fmt.Println("Saving credentials")

	sharedCreds := saml2aws.NewSharedCredentials(loginFlags.Profile)

	err = sharedCreds.Save(aws.StringValue(resp.Credentials.AccessKeyId), aws.StringValue(resp.Credentials.SecretAccessKey), aws.StringValue(resp.Credentials.SessionToken))
	if err != nil {
		return errors.Wrap(err, "error saving credentials")
	}

	fmt.Println("Logged in as:", aws.StringValue(resp.AssumedRoleUser.Arn))
	fmt.Println("")
	fmt.Println("Your new access key pair has been stored in the AWS configuration")
	fmt.Printf("Note that it will expire at %v\n", resp.Credentials.Expiration.Local())
	fmt.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", loginFlags.Profile, "ec2 describe-instances).")

	fmt.Println("Saving config:", config.Filename)
	config.SaveUsername(loginDetails.Username)
	config.SaveHostname(loginDetails.Hostname)

	return nil
}

func resolveLoginDetails(hostname string, loginFlags *LoginFlags) (*saml2aws.LoginDetails, error) {

	loginDetails := new(saml2aws.LoginDetails)

	// fmt.Printf("loginFlags %+v\n", loginFlags)

	savedUsername, savedPassword, err := credentials.LookupCredentials(hostname)
	if err != nil {
		if !credentials.IsErrCredentialsNotFound(err) {
			return nil, errors.Wrap(err, "error loading saved password")
		}
	}

	// fmt.Printf("%s %s\n", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.Username != "" {
		loginDetails.Username = loginFlags.Username
	} else if savedUsername != "" {
		loginDetails.Username = savedUsername
	}

	// if you supply a password in a flag it takes precedence
	if loginFlags.Password != "" {
		loginDetails.Password = loginFlags.Password
	} else if savedPassword != "" {
		loginDetails.Password = savedPassword
	}

	// fmt.Printf("loginDetails %+v\n", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.SkipPrompt {
		return &saml2aws.LoginDetails{
			Username: loginDetails.Username,
			Password: loginDetails.Password,
			Hostname: loginFlags.Hostname,
		}, nil
	}

	return saml2aws.PromptForLoginDetails(savedUsername, hostname, savedPassword)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, samlAssertion string, loginFlags *LoginFlags) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		if loginFlags.RoleSupplied() {
			return saml2aws.LocateRole(awsRoles, loginFlags.RoleArn)
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

	if loginFlags.RoleSupplied() {
		return saml2aws.LocateRole(awsRoles, loginFlags.RoleArn)
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
