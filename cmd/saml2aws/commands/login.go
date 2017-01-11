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
)

// Login login to ADFS
func Login(profile, providerName string, skipVerify bool) error {

	config := saml2aws.NewConfigLoader("adfs")

	username, err := config.LoadUsername()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	hostname, err := config.LoadHostname()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	loginDetails, err := saml2aws.PromptForLoginDetails(username, hostname)
	if err != nil {
		return errors.Wrap(err, "error accepting password")
	}

	fmt.Printf("%s https://%s\n", providerName, loginDetails.Hostname)

	fmt.Printf("Authenticating to %s...\n", providerName)

	opts := &saml2aws.SAMLOptions{Provider: providerName, SkipVerify: skipVerify}

	provider, err := saml2aws.NewSAMLClient(opts)
	if err != nil {
		return errors.Wrap(err, "error building adfs client")
	}

	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error authenticating to adfs")

	}

	if samlAssertion == "" {
		fmt.Println("Response did not contain a valid SAML assertion")
		fmt.Println("Please check your username and password is correct")
		os.Exit(1)
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

	role, err := saml2aws.PromptForAWSRoleSelection(awsRoles)
	if err != nil {
		return errors.Wrap(err, "error selecting role")
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
		return errors.Wrap(err, "error retieving sts credentials using SAML")
	}

	fmt.Println("Saving credentials")

	sharedCreds := saml2aws.NewSharedCredentials(profile)

	err = sharedCreds.Save(aws.StringValue(resp.Credentials.AccessKeyId), aws.StringValue(resp.Credentials.SecretAccessKey), aws.StringValue(resp.Credentials.SessionToken))
	if err != nil {
		return errors.Wrap(err, "error saving credentials")
	}

	fmt.Println("Logged in as:", aws.StringValue(resp.AssumedRoleUser.Arn))
	fmt.Println("")
	fmt.Println("Your new access key pair has been stored in the AWS configuration")
	fmt.Printf("Note that it will expire at %v\n", resp.Credentials.Expiration.Local())
	fmt.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", profile, "ec2 describe-instances).")

	fmt.Println("Saving config:", config.Filename)
	config.SaveUsername(loginDetails.Username)
	config.SaveHostname(loginDetails.Hostname)

	return nil
}
