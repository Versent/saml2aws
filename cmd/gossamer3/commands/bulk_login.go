package commands

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awsCredentials "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// PrimaryRoleInput is the input to assume a primary role into secondary roles
type PrimaryRoleInput struct {
	RoleConfig       cfg.RoleConfig
	AccountRegionMap map[string]string
	Account          *cfg.IDPAccount
	Role             *g3.AWSRole
	SAMLAssertion    string

	channel chan PrimaryRoleOutput
}

// SecondaryRoleInput is the input to assume a secondary role based on a primary role
type SecondaryRoleInput struct {
	PrimaryCredentials *awsconfig.AWSCredentials
	RoleAssumption     cfg.RoleAssumption
	PrimaryInput       *PrimaryRoleInput

	channel chan SecondaryRoleOutput
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
func (input *PrimaryRoleInput) Assume(roleSessionName string, force bool, sharedCredsFile *awsconfig.CredentialsFile) {
	var creds *awsconfig.AWSCredentials
	var err error
	existingCreds := false

	// Select region with this priority:
	// 1. Role region
	// 2. AccountMap region
	// 3. Default region from IDPAccount configuration
	region := input.Account.Region
	accountNumber := strings.Split(input.RoleConfig.PrimaryRoleArn, ":")[4]
	if input.RoleConfig.Region != "" {
		region = input.RoleConfig.Region
	} else if r, ok := input.AccountRegionMap[accountNumber]; ok {
		region = r
	} else if region == "" {
		region = "us-east-1"
	}

	// Initialize logging
	fields := logrus.Fields{
		"Region": region,
	}
	if input.Role != nil {
		fields["Role"] = input.Role.RoleARN
		if logrus.GetLevel() >= logrus.DebugLevel {
			fields["SamlProvider"] = input.Role.PrincipalARN
		}
	}

	l := logrus.WithFields(fields)

	// Check for existing credentials if a profile is configured
	if input.RoleConfig.Profile != "" {
		l = l.WithField("Profile", input.RoleConfig.Profile)

		// Not forcing credential refresh, pull from file
		if !force {

			// Check if credentials are expired
			if !sharedCredsFile.Expired(input.RoleConfig.Profile) {
				creds, err = sharedCredsFile.Load(input.RoleConfig.Profile)
				existingCreds = creds != nil
			}
		}
	}

	// Get new credentials
	if force || err != nil || !existingCreds || input.RoleConfig.Profile == "" {
		// If session duration is defined at a role level, use that instead of the idp account level
		var sessDur = input.Account.SessionDuration
		if input.RoleConfig.SessionDuration > 0 {
			sessDur = input.RoleConfig.SessionDuration
		}
		l = l.WithField("Duration", fmt.Sprintf("%vs", sessDur))

		creds, err = loginToStsUsingRole(input.Role, sessDur, input.SAMLAssertion, region)
	}

	// Check for errors
	if err != nil {
		// Log the error
		l.Errorf(err.Error())

		// Send response through the channel
		input.channel <- PrimaryRoleOutput{
			Input: input,
			err:   err,
		}

		return
	}

	// Build success message
	successMessage := "Assumed parent role"
	if existingCreds {
		successMessage = "Using existing parent credentials"
	}

	// Log success
	l.Infof(successMessage)

	// Create channel and wait group for secondary assumptions
	c := make(chan SecondaryRoleOutput, len(input.RoleConfig.AssumeRoles))
	wg := &sync.WaitGroup{}

	// Loop through secondary assumptions from config
	for _, item := range input.RoleConfig.AssumeRoles {
		secondaryInput := SecondaryRoleInput{
			PrimaryCredentials: creds,
			RoleAssumption:     item,
			PrimaryInput:       input,
			channel:            c,
		}

		// Add to the wait group
		wg.Add(1)

		// Perform secondary assumption
		go secondaryInput.Assume(roleSessionName, force, sharedCredsFile)
	}

	// Create a channel to wait for completion of the wait group
	done := make(chan bool, 1)
	go func(ch chan bool) {
		wg.Wait()
		ch <- true
	}(done)

	output := PrimaryRoleOutput{
		Input:              input,
		PrimaryCredentials: creds,
	}

	for {
		select {
		case secondaryRole := <-c:
			if secondaryRole.err == nil {
				output.Output = append(output.Output, secondaryRole)
			}

			wg.Done()

		// Wait for completion channel
		case <-done:
			// Send output through the primary channel up the stack
			input.channel <- output
			return

		// Timeout if not completed in time
		case <-time.After(time.Second * time.Duration(input.Account.Timeout)):
			l.Errorf("Timed out assuming secondary credentials after %v seconds", input.Account.Timeout)
		}
	}
}

// Assume assumes a secondary role using the PrimaryRoleInput parent object
func (input *SecondaryRoleInput) Assume(roleSessionName string, force bool, sharedCredsFile *awsconfig.CredentialsFile) {
	var creds *awsconfig.AWSCredentials
	var err error
	existingCreds := false

	// Select region with this priority:
	// 1. Role region
	// 2. AccountMap region
	// 3. Default region from IDPAccount configuration
	region := input.PrimaryInput.Account.Region
	accountNumber := strings.Split(input.RoleAssumption.RoleArn, ":")[4]
	if input.RoleAssumption.Region != "" {
		region = input.RoleAssumption.Region
	} else if r, ok := input.PrimaryInput.AccountRegionMap[accountNumber]; ok {
		region = r
	} else if region == "" {
		region = "us-east-1"
	}

	// Initialize logging
	fields := logrus.Fields{
		"Role":    input.RoleAssumption.RoleArn,
		"Profile": input.RoleAssumption.Profile,
		"Region":  region,
	}
	if logrus.GetLevel() >= logrus.DebugLevel && input.PrimaryInput.Role != nil {
		fields["PrimaryRole"] = input.PrimaryInput.Role.RoleARN
	}
	l := logrus.WithFields(fields)

	// Generate a profile if one is not provided
	if input.RoleAssumption.Profile == "" {
		arnParts := strings.Split(input.RoleAssumption.RoleArn, ":")
		input.RoleAssumption.Profile = fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))
	}

	// Not forcing credential refresh, pull from file
	if !force {
		// Check if credentials are expired
		if !sharedCredsFile.Expired(input.RoleAssumption.Profile) {
			creds, err = sharedCredsFile.Load(input.RoleAssumption.Profile)
			existingCreds = creds != nil
		}
	}

	// Get new credentials if forced, error encountered, or credentials are not found
	if force || err != nil || !existingCreds {
		creds, err = assumeRole(input.PrimaryCredentials, input.RoleAssumption.RoleArn, roleSessionName, region)
	}

	output := SecondaryRoleOutput{
		Input:       input,
		Credentials: creds,
		err:         err,
	}

	if err != nil {
		// Log the error
		l.Error(err.Error())
	} else {
		// Log the success
		successMessage := "Assumed child role"
		if existingCreds {
			successMessage = "Using existing credentials"
		}
		l.Infof(successMessage)
	}

	// Send response up through the channel
	input.channel <- output
}

// BulkLogin login to multiple roles
func BulkLogin(loginFlags *flags.LoginExecFlags) error {
	// Create logger
	logger := logrus.WithField("command", "bulk-login")

	// Build the IDP account
	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	// Read configuration file
	roleConfig, err := cfg.LoadRoleConfig(loginFlags.BulkLoginConfig)
	if err != nil {
		log.Fatalln(err)
	}

	logger.Debugf("Role Config: %+v", roleConfig)

	// Check if any credentials need to be refreshed - only run when force is false
	logger.Debug("Check if credentials exist")

	// Load entire file from single location
	sharedCredsFile, err := awsconfig.LoadCredentialsFile()
	if err != nil {
		logger.Fatalln(errors.Wrap(err, "couldnt load aws credentials file"))
	}

	// Not forced, and not assuming all roles
	if !loginFlags.Force && !roleConfig.AssumeAllRoles {
		var primaryExpired = false             // Only prompt login if one of the parent credentials are expired
		var noCredsExpired = true              // If no creds are expired, then no need to assume any roles
		var rolesToAssume = []cfg.RoleConfig{} // Roles to assume if the primary is NOT expired
		var sessionRoleName = ""

		// Check if any parent credentials have expired
		for _, primary := range roleConfig.Roles {
			// Only check for expiration of parent role
			if primary.Profile != "" {
				if sharedCredsFile.Expired(primary.Profile) {
					logger.WithField("Role", primary.PrimaryRoleArn).Debugf("Creds have expired")
					primaryExpired = true
					noCredsExpired = false
					break
				}

				// Not expired, set the session role name. Only need this once since it should always be the same
				if sessionRoleName == "" {
					creds, err := sharedCredsFile.Load(primary.Profile)
					if err != nil {
						return errors.Wrap(err, "error creating shared creds")
					}
					name, err := getRoleSessionNameFromCredentials(account, creds)
					if err != nil {
						return errors.Wrap(err, "error getting role session name from creds")
					}

					if !strings.HasPrefix(name, "gossamer3-") {
						name = "gossamer3-" + name
					}
					sessionRoleName = name
				}
			}

			// Create a copy of the primary, to only add roles that are expired
			var primaryCopy = cfg.RoleConfig{
				PrimaryRoleArn: primary.PrimaryRoleArn,
				Profile:        primary.Profile,
				AssumeRoles:    []cfg.RoleAssumption{},
			}

			// Primary role not expired, check secondary roles
			// if a secondary role IS expired, add to list of rolesToAssume

			for _, secondary := range primary.AssumeRoles {
				// If profile is empty, generate one
				if secondary.Profile == "" {
					arnParts := strings.Split(secondary.RoleArn, ":")
					secondary.Profile = fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))
				}

				if sharedCredsFile.Expired(secondary.Profile) {
					logger.WithField("SecondaryRole", secondary.RoleArn).Debugf("Creds have expired")

					// Secondary is expired. Add secondary role to primary
					noCredsExpired = false

					// Add just the secondary expired role to the primary role assumptions
					primaryCopy.AssumeRoles = append(primaryCopy.AssumeRoles, secondary)

					// // If primary has no profile, prompt for login
					if primary.Profile == "" {
						primaryExpired = true
						break
					}
				}
			}

			// If any secondaries are expired, add them to rolesToAssume
			if len(primaryCopy.AssumeRoles) > 0 {
				rolesToAssume = append(rolesToAssume, primaryCopy) // Add entire primary if any of the secondaries are expired
			}
		}

		// If no creds are expired, return to sender, no work to be done
		if noCredsExpired {
			logger.Infof("Credentials are not expired (use --force to login anyways)")
			return nil
		}

		// BEFORE asking for login details, check if any primary creds are expired
		if !primaryExpired {
			// Get the role session name
			logger.Infof("Using primary role session to assume child roles. No need to login")

			return bulkAssumeAsync(sharedCredsFile, rolesToAssume, account, roleConfig, sessionRoleName, false, true, "")
		}
	}

	// Pull the login details
	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	// Validate login details
	err = loginDetails.Validate()
	if err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	// Create saml client for the provider
	provider, err := g3.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	// Authenticate against IDP
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

	// Get the role session name to use in role assumptions
	roleSessionName, err := g3.ExtractRoleSessionName(samlAssertionData)
	if err != nil {
		return errors.Wrap(err, "error extracting role session name")
	}

	// Set the roleSessionName for later
	roleSessionName = fmt.Sprintf("gossamer3-%s", roleSessionName)

	if roleConfig.AssumeAllRoles {
		logger.Infof("Grabbing all roles and ignoring duplicates...")
		// Check for duplicate roles (Only when assume_all_roles)
		// Populate role config using all roles from aws saml assertion
		samlAssertionRoles, err := grabAllAwsRoles(samlAssertionData)
		if err != nil {
			return errors.Wrap(err, "error getting your aws roles from saml assertion")
		}

		for _, role := range samlAssertionRoles {
			var duplicate = false
			for _, configRole := range roleConfig.Roles {
				// Look for duplicate role
				if role.RoleARN == configRole.PrimaryRoleArn {
					duplicate = true

					if configRole.Profile == "" {
						arnParts := strings.Split(configRole.PrimaryRoleArn, ":")
						configRole.Profile = fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))
					}

					break
				}
			}

			if !duplicate {
				arnParts := strings.Split(role.RoleARN, ":")
				profile := fmt.Sprintf("%s/%s", arnParts[4], strings.TrimPrefix(arnParts[5], "role/"))

				roleConfig.Roles = append(roleConfig.Roles, cfg.RoleConfig{
					PrimaryRoleArn: role.RoleARN,
					Profile:        profile,
				})
			}

		}
		{
			// Log using debug all roles
			bs, err := json.Marshal(roleConfig.Roles)
			if err == nil {
				logger.Debugf("Got %v groups to assume roles from file & from AWS", len(roleConfig.Roles))
				logger.Debugln(string(bs))
			}
		}
		logger.Debugf("Got groups: %+v", roleConfig.Roles)
	}

	return bulkAssumeAsync(sharedCredsFile, roleConfig.Roles, account, roleConfig, roleSessionName, loginFlags.Force, false, samlAssertion)
}

// bulkAssumeAsync assumes all primary and secondary roles given in the roles slice. If useExistingCreds is true, the samlAssertion
// is NOT needed
func bulkAssumeAsync(sharedCredsFile *awsconfig.CredentialsFile, roles []cfg.RoleConfig,
	account *cfg.IDPAccount, roleConfig *cfg.BulkRoleConfig, roleSessionName string, force, useExistingCreds bool, samlAssertion string) error {

	logger := logrus.WithFields(logrus.Fields{
		"Action":           "Bulk Assume",
		"UseExistingCreds": useExistingCreds,
	})

	wg := &sync.WaitGroup{}
	ch := make(chan PrimaryRoleOutput, len(roles))
	done := make(chan bool, 1)

	// Assume each primary role
	for _, role := range roles {
		var primaryRole *g3.AWSRole // primaryRole is only used if useExistingCreds is false
		if !useExistingCreds {
			primary, err := getPrimaryRole(samlAssertion, account, role.PrimaryRoleArn)
			if err != nil {
				err = errors.Wrap(err, "Failed to assume parent role, please check whether you are permitted to assume the given role for the AWS service")
				logger.Errorf(err.Error())
				continue
			}
			primaryRole = primary
		}

		input := PrimaryRoleInput{
			AccountRegionMap: roleConfig.AccountRegionMap,
			RoleConfig:       role,
			Account:          account,
			Role:             primaryRole,
			SAMLAssertion:    samlAssertion,
			channel:          ch,
		}

		wg.Add(1)

		// Perform role assumption
		go input.Assume(roleSessionName, force, sharedCredsFile)
	}

	// Done channel
	go func(ch chan bool) {
		wg.Wait()
		ch <- true
	}(done)

	for {
		select {
		case creds := <-ch:
			// Handles if the primary role fails
			if creds.err != nil {
				logger.Debugf("Error assuming role: %s", creds.err.Error())
				wg.Done()
				continue
			}

			// Handle primary creds, only need to save primary if NOT using existing creds
			if creds.Input.RoleConfig.Profile != "" && !useExistingCreds {
				if err := sharedCredsFile.StoreCreds(creds.Input.RoleConfig.Profile, creds.PrimaryCredentials); err != nil {
					return errors.Wrap(err, "error saving credentials")
				}
			}

			// Handle secondary creds
			for _, childCreds := range creds.Output {
				if err := sharedCredsFile.StoreCreds(childCreds.Input.RoleAssumption.Profile, childCreds.Credentials); err != nil {
					return errors.Wrap(err, "error saving child credentials")
				}
			}
			wg.Done()

		case <-done:
			if err := sharedCredsFile.SaveFile(); err != nil {
				log.Fatalf("Error storing new credentials: %v", err)
			}
			logger.Infof("Done!")
			return nil

		// Timeout
		case <-time.After(time.Second * time.Duration(account.Timeout)):
			// TODO: Should i store what i have so far?
			logger.Errorf("Timed out after %v seconds", account.Timeout)
			return errors.New("timed out while assuming roles")
		}
	}
}

// getPrimaryRole : Read the SAML assertion to find a specific role
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

// resolvePrimaryRole : Finds a Role ARN in the SAML assertion and returns it as an AWSRole object
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

// assumeRole : Assumes a child role using provided credentials
func assumeRole(parentCreds *awsconfig.AWSCredentials, roleArn string, roleSessionName string, region string) (*awsconfig.AWSCredentials, error) {
	// Create config using supplied region and credentials
	config := aws.NewConfig().WithRegion(region).WithCredentials(
		awsCredentials.NewStaticCredentials(
			parentCreds.AWSAccessKey,
			parentCreds.AWSSecretKey,
			parentCreds.AWSSessionToken,
		),
	)

	// Create session and client
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            *config,
		SharedConfigFiles: []string{},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	// Set user agent handler
	awsconfig.OverrideUserAgent(sess)

	svc := sts.New(sess)

	// Generate input
	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),         // Required
		RoleSessionName: aws.String(roleSessionName), // Required
	}

	// Create exponential backoff (max duration 15 seconds)
	eb := backoff.NewExponentialBackOff()
	eb.MaxElapsedTime = time.Second * 15

	// Create the backoff function
	var resp *sts.AssumeRoleOutput
	var respErr error = nil
	attempt := 0
	webhookBackoff := func() error {
		// Assume the role
		resp, err = svc.AssumeRole(params)
		respErr = err
		attempt++

		// Exit backoff when any AWS error comes back
		if _, ok := err.(awserr.RequestFailure); ok {
			return nil
		}

		return err
	}

	// Create notification handler for logging
	notifyHandler := func(err error, delay time.Duration) {
		logrus.WithError(err).WithFields(logrus.Fields{
			"Delay":   delay,
			"Role":    roleArn,
			"Attempt": attempt,
		}).Debugf("Assume Role failed")
	}

	// Assume role with exponential backoff
	_ = backoff.RetryNotify(webhookBackoff, eb, notifyHandler)
	if respErr != nil {
		return nil, errors.Wrap(respErr, "error retrieving STS credentials")
	}

	// Return the credentials
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
