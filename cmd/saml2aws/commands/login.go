package commands

import (
	"encoding/base64"
	"fmt"
	"os"
        "encoding/json"
        "net/http"
        "io/ioutil"
        "strings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/elmobp/saml2aws"
)

// this checks pete for the aws ID..if status is inactive will not return result
func retrieve_awsid(clientid string) string {
  response, err := http.Get("http://pete.production.maint.bulletproof.net/api/v1/awsid/"+clientid)
  if err != nil {call_error(err)}

  defer response.Body.Close()
  if (response.StatusCode != 200) {
    fmt.Println("Something went wrong when interacting with PETE")
    os.Exit(1)
  }
  contents, err := ioutil.ReadAll(response.Body)
  if err != nil {call_error(err)}

  var m interface{}
  errj := json.Unmarshal(contents, &m)
  if errj != nil {call_error(errj)}

  f := m.(map[string]interface{})
  if string(f["status"].(string)) == "inactive" {
    fmt.Println(clientid, "is inactive in PETE, please connect to an active account.")
    os.Exit(1)
  }
  return string(f["awsid"].(string))
}


// Login login to ADFS
func Login(profile string, skipVerify bool, clientId string, role string) error {

	config := saml2aws.NewConfigLoader("adfs")

	username, err := config.LoadUsername()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

	hostname, err := config.LoadHostname()
	if err != nil {
		return errors.Wrap(err, "error loading config file")
	}

        password, err := config.LoadPassword()
        if err != nil {
                return errors.Wrap(err, "error loading config file")
        }  

        loginDetails :=  &saml2aws.LoginDetails{
                Username: strings.TrimSpace(username),
                Password: strings.TrimSpace(password),
                Hostname: strings.TrimSpace(hostname),
        }



	adfs, err := saml2aws.NewADFSClient(skipVerify)
	if err != nil {
		return errors.Wrap(err, "error building adfs client")
	}

	samlAssertion, err := adfs.Authenticate(loginDetails)
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

        awsid := retrieve_awsid(clientId)
        PrincipalARN := "arn:aws:iam::"+awsid+":saml-provider/ADFS"
        RoleARN := "arn:aws:iam::"+awsid+":role/"+role

	sess, err := session.NewSession()
	if err != nil {
		return errors.Wrap(err, "failed to create session")
	}

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  aws.String(PrincipalARN), // Required
		RoleArn:       aws.String(RoleARN),      // Required
		SAMLAssertion: aws.String(samlAssertion),     // Required
	}

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return errors.Wrap(err, "PrincipalARN: " + PrincipalARN + " RoleARN: " + RoleARN + "error retieving sts credentials using SAML")
	}
        config.SaveUsername(loginDetails.Username)
        config.SaveHostname(loginDetails.Hostname)
        config.SavePassword(loginDetails.Password, loginDetails.Username)

        cwd, err := os.Getwd()
        if err != nil {
         panic(err)
        }
        os.Setenv("AWS_ACCESS_KEY_ID", *resp.Credentials.AccessKeyId)
        os.Setenv("AWS_SECRET_ACCESS_KEY", *resp.Credentials.SecretAccessKey)
        os.Setenv("AWS_SESSION_TOKEN", *resp.Credentials.SessionToken)
        os.Setenv("AWS_SECURITY_TOKEN", *resp.Credentials.SessionToken)
        os.Setenv("CLIENTID", clientId);
        shell := os.Getenv("SHELL")
        pa := os.ProcAttr {
         Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
         Dir: cwd,
        }
        proc, err := os.StartProcess(shell, []string{""}, &pa)
        if err != nil {
         panic(err)
        } 
        state, err := proc.Wait()
        if err != nil {
         panic(err)
        }
        fmt.Printf("<< Exited shell: %s\n", state.String())
	return nil
}

func call_error(error_resp error) {
  fmt.Println(error_resp)
  os.Exit(1)
}
