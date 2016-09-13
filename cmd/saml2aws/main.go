package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/versent/saml2aws"
)

var (
	// /verbose      = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	skipVerify   = kingpin.Flag("skip-verify", "Skip verification of server certificate.").Short('s').Bool()
	profileName  = kingpin.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").String()
	adfsHostname = kingpin.Arg("hostname", "Hostname of the ADFS service").Required().String()

	// Version app version
	Version = "1.0.0"
)

func main() {
	log.SetFlags(log.Lshortfile)

	kingpin.Version(Version)
	kingpin.Parse()

	sharedCreds := saml2aws.NewSharedCredentials(*profileName)

	err := sharedCreds.Exists()
	if err != nil {
		log.Fatalf("error loading aws credentials file: %v", err)
	}

	config := saml2aws.NewConfig("adfs")

	username, err := config.LoadUsername()
	if err != nil {
		log.Fatalf("error loading config file: %v", err)
	}

	adfsURL := fmt.Sprintf("https://%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", *adfsHostname)

	fmt.Printf("ADFS https://%s\n", *adfsHostname)

	user, err := saml2aws.PromptForLoginCreds(username)
	if err != nil {
		log.Fatalf("error accepting password: %v", err)
	}

	fmt.Println("Authenticating to ADFS...")

	adfs, err := saml2aws.NewADFSClient(adfsURL, *skipVerify)
	if err != nil {
		log.Fatalf("error building adfs client: %v", err)
	}

	samlAssertion, err := adfs.Authenticate(user)
	if err != nil {
		log.Fatalf("error authenticating to adfs: %v", err)
	}

	if samlAssertion == "" {
		fmt.Println("Response did not contain a valid SAML assertion")
		fmt.Println("Please check your username and password is correct")
		os.Exit(1)
	}

	data, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		log.Fatalf("error decoding saml assertion: %v", err)
	}

	roles, err := saml2aws.ExtractAwsRoles(data)
	if err != nil {
		log.Fatalf("error parsing aws roles: %v", err)
	}

	if len(roles) == 0 {
		fmt.Println("No roles to assume")
		fmt.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	role, err := saml2aws.PromptForAWSRoleSelection(roles)
	if err != nil {
		log.Fatalf("error selecting role: %v", err)
	}

	fmt.Println("Selected role:", role.RoleARN)

	sess, err := session.NewSession()
	if err != nil {
		fmt.Println("failed to create session,", err)
		return
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  aws.String(role.PrincipalARN), // Required
		RoleArn:       aws.String(role.RoleARN),      // Required
		SAMLAssertion: aws.String(samlAssertion),     // Required
	}

	fmt.Println("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		log.Fatalf("error retieving sts credentials using SAML: %v", err)
	}

	fmt.Println("Saving credentials")

	err = sharedCreds.Save(aws.StringValue(resp.Credentials.AccessKeyId), aws.StringValue(resp.Credentials.SecretAccessKey), aws.StringValue(resp.Credentials.SessionToken))
	if err != nil {
		log.Fatalf("error saving credentials: %v", err)
	}

	fmt.Println("")
	fmt.Println("Your new access key pair has been stored in the AWS configuration")
	fmt.Printf("Note that it will expire at %v\n", resp.Credentials.Expiration.Local())
	fmt.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", *profileName, "ec2 describe-instances).")

	config.SaveUsername(user.Username)
}
