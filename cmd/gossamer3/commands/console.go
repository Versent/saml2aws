package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awsCredentials "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
)

const (
	commercialFederationURL = "https://signin.aws.amazon.com/federation"
	govFederationURL        = "https://signin.amazonaws-us-gov.com/federation"
	issuer                  = "gossamer3"
)

// Console open the aws console from the CLI
func Console(consoleFlags *flags.ConsoleFlags) error {

	account, err := buildIdpAccount(consoleFlags.LoginExecFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if gossamer3 exec is run on a new
	// system prior to creating $HOME/.aws
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required to create them")
		return nil
	}

	awsCreds, err := loadOrLogin(account, sharedCreds, consoleFlags)
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	if consoleFlags.LoginExecFlags.ExecProfile != "" {
		// Assume the desired role before generating env vars
		awsCreds, err = assumeRoleWithProfile(consoleFlags.LoginExecFlags.ExecProfile, consoleFlags.LoginExecFlags.CommonFlags.SessionDuration)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("error acquiring credentials for profile: %s", consoleFlags.LoginExecFlags.ExecProfile))
		}
	} else if consoleFlags.LoginExecFlags.AssumeChildRole != "" {
		roleSessionName, err := getRoleSessionNameFromCredentials(account, awsCreds)
		if err != nil {
			return errors.Wrap(err, "error getting role session name")
		}

		// Assume a child role
		awsCreds, err = assumeRole(
			awsCreds,
			consoleFlags.LoginExecFlags.AssumeChildRole,
			roleSessionName,
			account.Region,
		)
		if err != nil {
			return errors.Wrap(err, "error assuming role "+consoleFlags.LoginExecFlags.AssumeChildRole)
		}
	}

	federationURL := commercialFederationURL
	if strings.HasPrefix(account.Region, "us-gov-") {
		federationURL = govFederationURL
	}

	log.Printf("Presenting credentials for %s to %s", account.Profile, federationURL)
	return federatedLogin(awsCreds, consoleFlags)
}

func loadOrLogin(account *cfg.IDPAccount, sharedCreds *awsconfig.CredentialsProvider, execFlags *flags.ConsoleFlags) (*awsconfig.AWSCredentials, error) {

	var err error

	if execFlags.LoginExecFlags.Force {
		log.Println("force login requested")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		if err != awsconfig.ErrCredentialsNotFound {
			return nil, errors.Wrap(err, "failed to load credentials")
		}
		log.Println("credentials not found triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	if time.Until(awsCreds.Expires) < 0 {
		log.Println("expired credentials triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	ok, err := checkToken(account)
	if err != nil {
		return nil, errors.Wrap(err, "error validating token")
	}

	if !ok {
		log.Println("aws rejected credentials triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	return awsCreds, nil
}

func loginRefreshCredentials(sharedCreds *awsconfig.CredentialsProvider, execFlags *flags.LoginExecFlags) (*awsconfig.AWSCredentials, error) {
	err := Login(execFlags)
	if err != nil {
		return nil, errors.Wrap(err, "error logging in")
	}

	return sharedCreds.Load()
}

func federatedLogin(creds *awsconfig.AWSCredentials, consoleFlags *flags.ConsoleFlags) error {
	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    creds.AWSAccessKey,
		"sessionKey":   creds.AWSSecretKey,
		"sessionToken": creds.AWSSessionToken,
	})
	if err != nil {
		return err
	}

	federationURL := commercialFederationURL
	if strings.HasPrefix(creds.Region, "us-gov-") {
		federationURL = govFederationURL
	}

	req, err := http.NewRequest("GET", federationURL, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string
	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		return err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return err
	}

	destination := "https://console.aws.amazon.com/"
	if strings.HasPrefix(creds.Region, "us-gov-") {
		destination = "https://console.amazonaws-us-gov.com/"
	}

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		federationURL,
		issuer,
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	// write the URL to stdout making it easy to capture seperately and use in a shell function
	if consoleFlags.Link {
		fmt.Println(loginURL)
		return nil
	}

	return open.Run(loginURL)
}

func getRoleSessionNameFromCredentials(account *cfg.IDPAccount, awsCreds *awsconfig.AWSCredentials) (string, error) {
	// Create config using supplied credentials and region
	config := aws.NewConfig().WithRegion(account.Region).WithCredentials(
		awsCredentials.NewStaticCredentials(
			awsCreds.AWSAccessKey,
			awsCreds.AWSSecretKey,
			awsCreds.AWSSessionToken,
		),
	)

	// Create session
	sess, err := session.NewSession(config)
	if err != nil {
		return "", errors.Wrap(err, "failed to create session")
	}

	// Set user agent handler
	awsconfig.OverrideUserAgent(sess)

	// Call to STS Get Caller Identity
	svc := sts.New(sess)
	resp, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", errors.Wrap(err, "failed to get caller identity")
	}

	// Extract the role session name from the arn (everything after the final /)
	arn := aws.StringValue(resp.Arn)
	arnParts := strings.Split(arn, "/")
	roleSessionName := arnParts[len(arnParts)-1]

	return roleSessionName, nil
}
