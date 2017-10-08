package credentials

import (
	"fmt"

	"github.com/versent/saml2aws"
)

// LookupCredentials lookup an existing set of credentials and validate it.
func LookupCredentials(loginDetails *saml2aws.LoginDetails) error {

	username, password, err := CurrentHelper.Get(fmt.Sprintf("https://%s", loginDetails.Hostname))
	if err != nil {
		return err
	}

	loginDetails.Username = username
	loginDetails.Password = password

	return nil
}

// SaveCredentials save the user credentials.
func SaveCredentials(hostname, username, password string) error {

	creds := &Credentials{
		ServerURL: fmt.Sprintf("https://%s", hostname),
		Username:  username,
		Secret:    password,
	}

	return CurrentHelper.Add(creds)
}
