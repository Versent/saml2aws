package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

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

// PrimaryRoleInput is the input to assume a primary role into secondary roles
type PrimaryRoleInput struct {
	RoleConfig    cfg.RoleConfig
	Account       *cfg.IDPAccount
	Role          *g3.AWSRole
	SAMLAssertion string

	channel chan PrimaryRoleOutput
	wg      *sync.WaitGroup
}

// SecondaryRoleInput is the input to assume a secondary role based on a primary role
type SecondaryRoleInput struct {
	PrimaryCredentials *awsconfig.AWSCredentials
	RoleAssumption     cfg.RoleAssumption
	PrimaryInput       *PrimaryRoleInput

	channel chan SecondaryRoleOutput
	wg      *sync.WaitGroup
}

// PrimaryRoleOutput is the output of assuming the primary role
type PrimaryRoleOutput struct {
	Input              *PrimaryRoleInput
	PrimaryCredentials *awsconfig.AWSCredentials
	Output             []SecondaryRoleOutput

	err error
}

// SecondaryRoleOutput is the output of a secondary role assumption
type SecondaryRoleOutput struct {
	Input       *SecondaryRoleInput
	Credentials *awsconfig.AWSCredentials

	err error
}

// Assume assumes a primary role, returning the credentials to assume secondary role if needed
func (input *PrimaryRoleInput) Assume(roleSessionName string) {
	l := logrus.WithFields(logrus.Fields{
		"Role":         input.Role.RoleARN,
		"SamlProvider": input.Role.PrincipalARN,
	})

	if input.RoleConfig.Profile != "" {
		l = l.WithField("Profile", input.RoleConfig.Profile)
	}

	creds, err := loginToStsUsingRole(input.Account, input.Role, input.SAMLAssertion)
	if err != nil {
		l.Errorf(err.Error())

		input.channel <- PrimaryRoleOutput{
			Input: input,
			err:   err,
		}
		input.wg.Done()
		return
	}

	l.Infof("Parent assumed")

	c := make(chan SecondaryRoleOutput, len(input.RoleConfig.AssumeRoles))
	wg := &sync.WaitGroup{}

	for _, item := range input.RoleConfig.AssumeRoles {
		secondaryInput := SecondaryRoleInput{
			PrimaryCredentials: creds,
			RoleAssumption:     item,
			PrimaryInput:       input,
			wg:                 wg,
			channel:            c,
		}

		wg.Add(1)
		go secondaryInput.Assume(roleSessionName)
	}

	done := make(chan bool, 1)

	go func(ch chan bool) {
		wg.Wait()
		ch <- true
	}(done)

	select {
	case <-done:
		output := PrimaryRoleOutput{
			Input:              input,
			PrimaryCredentials: creds,
		}

		close(c)

		for item := range c {
			if item.err != nil {
				output.err = errors.Wrap(item.err, "")
			} else {
				output.Output = append(output.Output, item)
			}
		}

		input.channel <- output
		input.wg.Done()

	case <-time.After(time.Second * 10):
		logrus.Errorf("Timed out assuming secondary credentials")
	}
}

// Assume assumes a secondary role using the PrimaryRoleInput parent object
func (input *SecondaryRoleInput) Assume(roleSessionName string) {
	if input.RoleAssumption.Profile == "" {
		arnParts := strings.Split(input.RoleAssumption.RoleArn, ":")
		input.RoleAssumption.Profile = fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))
	}

	creds, err := assumeRole(input.PrimaryInput.Account, input.PrimaryCredentials, input.RoleAssumption.RoleArn, roleSessionName)
	output := SecondaryRoleOutput{
		Input:       input,
		Credentials: creds,
		err:         err,
	}

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"Profile":     input.RoleAssumption.Profile,
			"Role":        input.RoleAssumption.RoleArn,
			"PrimaryRole": input.PrimaryInput.Role.RoleARN,
		}).Error(err.Error())
	} else {
		logrus.WithFields(logrus.Fields{
			"Profile":     input.RoleAssumption.Profile,
			"Role":        input.RoleAssumption.RoleArn,
			"PrimaryRole": input.PrimaryInput.Role.RoleARN,
		}).Infof("Successfully assumed role")
	}

	input.channel <- output
	input.wg.Done()
}

// BulkLogin login to multiple roles
func BulkLogin(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "bulk-login")

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

	// Create channel and wait group
	wg := &sync.WaitGroup{}
	ch := make(chan PrimaryRoleOutput, len(roleConfig.Roles))
	done := make(chan bool, 1)

	for _, item := range roleConfig.Roles {
		primaryRole, err := getPrimaryRole(samlAssertion, account, item.PrimaryRoleArn)
		if err != nil {
			err := errors.Wrap(err, "Failed to assume parent role, please check whether you are permitted to assume the given role for the AWS service")
			logrus.Errorf(err.Error())
			continue
		}

		// TODO: Check if creds are not expired
		logrus.Debugf("Logging into %s using SAML", primaryRole.RoleARN)

		input := PrimaryRoleInput{
			RoleConfig:    item,
			Account:       account,
			Role:          primaryRole,
			SAMLAssertion: samlAssertion,
			channel:       ch,
			wg:            wg,
		}
		wg.Add(1)

		// Perform role assumption
		go input.Assume(roleSessionName)
	}

	// Wait for all the wait groups to finish
	go func(ch chan bool) {
		wg.Wait()
		ch <- true
	}(done)

	select {
	case <-done:
		close(ch)

		// Save credentials
		for creds := range ch {
			if creds.Input.RoleConfig.Profile != "" {
				sharedCreds := awsconfig.NewSharedCredentials(creds.Input.RoleConfig.Profile)
				if err := sharedCreds.Save(creds.PrimaryCredentials); err != nil {
					return errors.Wrap(err, "error saving credentials")
				}
			}

			// Handle secondary
			for _, childCreds := range creds.Output {
				sharedCreds := awsconfig.NewSharedCredentials(childCreds.Input.RoleAssumption.Profile)
				if err := sharedCreds.Save(childCreds.Credentials); err != nil {
					return errors.Wrap(err, "error saving credentials")
				}
			}
		}

	case <-time.After(time.Second * 10):
		logrus.Errorf("Timed out")
		return errors.New("timed out while assuming roles")
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
