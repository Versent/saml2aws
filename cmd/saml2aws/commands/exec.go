package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws"
)

// Exec execute the supplied command after seeding the environment
func Exec(profile string, skipVerify bool, cmdline []string) error {

	if len(cmdline) < 1 {
		return fmt.Errorf("Command to execute required.")
	}

	ok, err := checkToken(profile)
	if err != nil {
		return errors.Wrap(err, "error validating token")
	}

	if !ok {
		err = Login(profile, skipVerify)
	}
	if err != nil {
		return errors.Wrap(err, "error logging in")
	}

	sharedCreds := saml2aws.NewSharedCredentials(profile)

	id, secret, token, err := sharedCreds.Load()
	if err != nil {
		return errors.Wrap(err, "error loading credentials")
	}

	c := strings.Join(cmdline, " ")

	cs := []string{"/bin/sh", "-c", c}
	cmd := exec.Command(cs[0], cs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), buildEnvVars(id, secret, token)...)

	return cmd.Run()
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

	resp, err := svc.GetCallerIdentity(params)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ExpiredToken" {
				return false, nil
			}
		}

		return false, err
	}

	fmt.Println("Running command as:", aws.StringValue(resp.Arn))
	return true, nil
}

func buildEnvVars(id, secret, token string) []string {
	return []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", id),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", secret),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", token),
		fmt.Sprintf("AWS_SECURITY_TOKEN=%s", token),
		fmt.Sprintf("EC2_SECURITY_TOKEN=%s", token),
	}
}
