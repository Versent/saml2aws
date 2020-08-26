package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	awsCredentials "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// BulkLogin login to multiple roles
func BulkLogin(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	// Read configuration file
	roleConfig, err := cfg.LoadRoleConfig(loginFlags.BulkLoginConfig)
	if err != nil {
		log.Fatalln(err)
	}

	//logger.Debug("check if Creds Exist")
	//
	//// this checks if the credentials file has been created yet
	//exist, err := sharedCreds.CredsExists()
	//if err != nil {
	//	return errors.Wrap(err, "error loading credentials")
	//}
	//if !exist {
	//	log.Println("unable to load credentials, login required to create them")
	//	return nil
	//}
	//
	//if !sharedCreds.Expired() && !loginFlags.Force {
	//	log.Println("credentials are not expired skipping")
	//	return nil
	//}

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

	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return errors.Wrap(err, "error decoding saml assertion")
	}

	roleSessionName, err := g3.ExtractRoleSessionName(samlAssertionData)
	if err != nil {
		return errors.Wrap(err, "error extracting role session name")
	}
	roleSessionName = fmt.Sprintf("gossamer3-%s", roleSessionName)

	for _, item := range roleConfig.Roles {
		primaryRole, err := getPrimaryRole(samlAssertion, account, item.PrimaryRoleArn)
		if err != nil {
			return errors.Wrap(err, "Failed to assume role, please check whether you are permitted to assume the given role for the AWS service")
		}
		log.Println("Selected role:", primaryRole.RoleARN)

		// TODO: Check if creds are not expired
		logrus.Debugf("Logging into %s using SAML", primaryRole.RoleARN)
		awsCreds, err := loginToStsUsingRole(account, primaryRole, samlAssertion)
		if err != nil {
			return errors.Wrap(err, "error logging into aws role using saml assertion")
		}

		if item.Profile != "" {
			sharedCreds := awsconfig.NewSharedCredentials(item.Profile)
			sharedCreds.Save(awsCreds)
		}

		// Assume child roles
		for _, childRole := range item.AssumeRoles {
			profile := childRole.Profile
			if profile == "" {
				arnParts := strings.Split(childRole.RoleArn, ":")
				profile = fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))
			}

			sharedCreds := awsconfig.NewSharedCredentials(profile)

			// TODO: Check if creds are not expired

			logrus.Debugf("Assuming child role %s", childRole.RoleArn)
			childCreds, err := assumeRole(account, awsCreds, childRole.RoleArn, roleSessionName)
			if err != nil {
				return err
			}

			if err := sharedCreds.Save(childCreds); err != nil {
				return errors.Wrap(err, "error saving credentials")
			}
		}
	}

	return nil
}

func getPrimaryRole(samlAssertion string, account *cfg.IDPAccount, roleArn string) (*g3.AWSRole, error) {
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	roles, err := g3.ExtractAwsRoles(data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	if len(roles) == 0 {
		log.Println("No roles to assume")
		log.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	awsRoles, err := g3.ParseAWSRoles(roles)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	return resolvePrimaryRole(awsRoles, samlAssertion, account, roleArn)
}

func resolvePrimaryRole(awsRoles []*g3.AWSRole, samlAssertion string, account *cfg.IDPAccount, roleArn string) (*g3.AWSRole, error) {
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

	return g3.LocateRole(awsRoles, roleArn)
}

func assumeRole(account *cfg.IDPAccount, parentCreds *awsconfig.AWSCredentials, roleArn string, roleSessionName string) (*awsconfig.AWSCredentials, error) {

	config := aws.NewConfig().WithRegion(account.Region).WithCredentials(
		awsCredentials.NewStaticCredentials(
			parentCreds.AWSAccessKey,
			parentCreds.AWSSecretKey,
			parentCreds.AWSSessionToken,
		),
	)

	sess, err := session.NewSession(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),         // Required
		RoleSessionName: aws.String(roleSessionName), // Required
		DurationSeconds: aws.Int64(int64(account.SessionDuration)),
	}

	log.Println("Requesting AWS credentials")

	resp, err := svc.AssumeRole(params)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving STS credentials")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           account.Region,
	}, nil
}
