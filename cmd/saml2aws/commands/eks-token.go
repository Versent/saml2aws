package commands

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/awsconfig"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"log"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
	"time"
)

const (
	kind       = "ExecCredential"
	apiVersion = "client.authentication.k8s.io/v1"
)

type tokenOutput struct {
	Kind       string            `json:"kind"`
	ApiVersion string            `json:"apiVersion"`
	Status     tokenOutputStatus `json:"status"`
}
type tokenOutputStatus struct {
	ExpirationTimestamp string `json:"expirationTimestamp"`
	Token               string `json:"token"`
}

func EksToken(configFlags *flags.LoginExecFlags) error {
	account, err := buildIdpAccount(configFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	sharedCreds := awsconfig.NewSharedCredentials(account.Profile, account.CredentialsFile)

	// this checks if the credentials file has been created yet
	exist, err := sharedCreds.CredsExists()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}
	if !exist {
		log.Println("unable to load credentials, login required")
		return nil
	}

	awsCreds, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	if awsCreds.Expires.Sub(time.Now()) < 0 {
		if err := Login(configFlags); err != nil {
			return errors.Wrap(err, "error logging in")
		}
		awsCreds, err = sharedCreds.Load()
		if err != nil {
			return errors.Wrap(err, "error loading credentials")
		}
	}

	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return errors.Wrap(err, "failed to create token generator")
	}

	sess, err := session.NewSession(&aws.Config{
		CredentialsChainVerboseErrors: aws.Bool(true),
		Region:                        aws.String(awsCreds.Region),
		Credentials:                   credentials.NewStaticCredentials(awsCreds.AWSAccessKey, awsCreds.AWSSecretKey, awsCreds.AWSSessionToken),
	})
	if err != nil {
		return errors.Wrap(err, "failed to create aws session")
	}

	opts := &token.GetTokenOptions{
		Region:    configFlags.CommonFlags.Region,
		ClusterID: configFlags.ClusterName,
		Session:   sess,
	}
	eksToken, err := gen.GetWithOptions(opts)
	if err != nil {
		return errors.Wrap(err, "error generating token")
	}

	output := &tokenOutput{
		Kind:       kind,
		ApiVersion: apiVersion,
		Status: tokenOutputStatus{
			ExpirationTimestamp: eksToken.Expiration.Format("2006-01-02T15:04:05Z"),
			Token:               eksToken.Token,
		},
	}
	jsonOutput, err := json.Marshal(output)
	if err != nil {
		return errors.Wrap(err, "error marshaling json")
	}

	fmt.Println(string(jsonOutput))
	return nil
}
