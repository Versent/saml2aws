package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/flags"
)

const (
	federationURL = "https://signin.aws.amazon.com/federation"
	issuer        = "saml2aws"
)

// Exec execute the supplied command after seeding the environment
func Console(consoleFlags *flags.ConsoleFlags) error {

	account, err := buildIdpAccount(consoleFlags.LoginExecFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile)

	// this checks if the credentials file has been created yet
	// can only really be triggered if saml2aws exec is run on a new
	// system prior to creating $HOME/.aws
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		fmt.Println("unable to load credentials, login required to create them")
		return nil
	}

	awsCreds, err := loadOrLogin(account, sharedCreds, consoleFlags)
	if err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("error loading credentials for profile: %s", consoleFlags.LoginExecFlags.ExecProfile))
	}
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
	}

	fmt.Printf("Presenting credentials for %s to %s\n", account.Profile, federationURL)
	return federatedLogin(awsCreds, consoleFlags)
}

func loadOrLogin(account *cfg.IDPAccount, sharedCreds *awsconfig.CredentialsProvider, execFlags *flags.ConsoleFlags) (*awsconfig.AWSCredentials, error) {

	var err error

	if execFlags.LoginExecFlags.Force {
		fmt.Println("force login requested")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		if err != awsconfig.ErrCredentialsNotFound {
			return nil, errors.Wrap(err, "failed to load credentials")
		}
		fmt.Println("credentials not found triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	if awsCreds.Expires.Sub(time.Now()) < 0 {
		fmt.Println("expired credentials triggering login")
		return loginRefreshCredentials(sharedCreds, execFlags.LoginExecFlags)
	}

	ok, err := checkToken(account.Profile)
	if err != nil {
		return nil, errors.Wrap(err, "error validating token")
	}

	if !ok {
		fmt.Println("aws rejected credentials triggering login")
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

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		federationURL,
		issuer,
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	if consoleFlags.Link {
		fmt.Println(loginURL)
		return nil
	}

	return open.Run(loginURL)
}
