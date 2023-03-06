package commands

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/shell"
)

// Exec execute the supplied command after seeding the environment
func Exec(execFlags *flags.LoginExecFlags, cmdline []string) error {

	if len(cmdline) < 1 {
		return fmt.Errorf("Command to execute required")
	}

	account, err := buildIdpAccount(execFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2aws exec is run on a new
	// system prior to creating $HOME/.aws
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	if time.Until(awsCreds.Expires) < 0 {
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

	if execFlags.ExecProfile != "" {
		// Assume the desired role before generating env vars
		awsCreds, err = assumeRoleWithProfile(execFlags.ExecProfile, execFlags.CommonFlags.SessionDuration)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("error acquiring credentials for profile: %s", execFlags.ExecProfile))
		}
	}

	return shell.ExecShellCmd(cmdline, shell.BuildEnvVars(awsCreds, account, execFlags))
}

// assumeRoleWithProfile uses an AWS profile (via ~/.aws/config) and performs (multiple levels of) role assumption
// This is extremely useful in the case of a central "authentication account" which then requires secondary, and
// often tertiary, role assumptions to acquire credentials for the target role.
func assumeRoleWithProfile(targetProfile string, sessionDuration int) (*awsconfig.AWSCredentials, error) {
	// AWS session config with verbose errors on chained credential errors
	config := *aws.NewConfig().WithCredentialsChainVerboseErrors(true)
	duration, _ := time.ParseDuration(strconv.Itoa(sessionDuration) + "s")

	// a session forcing usage of the aws config file, sets the target profile which will be found in the config
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:             config,
		Profile:            targetProfile,
		SharedConfigState:  session.SharedConfigEnable,
		AssumeRoleDuration: duration,
	}))

	// use an STS client to perform the multiple role assumptions
	stsClient := sts.New(sess)
	input := &sts.GetCallerIdentityInput{}
	_, err := stsClient.GetCallerIdentity(input)
	if err != nil {
		return nil, err
	}

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, err
	}
	expiredAt, err := sess.Config.Credentials.ExpiresAt()
	if err != nil {
		return nil, err
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:    creds.AccessKeyID,
		AWSSecretKey:    creds.SecretAccessKey,
		AWSSessionToken: creds.SessionToken,
		Expires:         expiredAt,
	}, nil
}

func checkToken(profile string) (bool, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: profile,
	})
	if err != nil {
		return false, err
	}

	svc := sts.New(sess)

	params := &sts.GetCallerIdentityInput{}

	_, err = svc.GetCallerIdentity(params)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ExpiredToken" || awsErr.Code() == "NoCredentialProviders" {
				return false, nil
			}
		}

		return false, err
	}

	return true, nil
}
