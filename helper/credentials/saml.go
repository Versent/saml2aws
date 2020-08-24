package credentials

import (
	"github.com/GESkunkworks/gossamer3/pkg/creds"
)

// LookupCredentials lookup an existing set of credentials and validate it.
func LookupCredentials(loginDetails *creds.LoginDetails, provider string) error {

	username, password, err := CurrentHelper.Get(loginDetails.URL)
	if err != nil {
		return err
	}

	loginDetails.Username = username
	loginDetails.Password = password
	return nil
}

// SaveCredentials save the user credentials.
func SaveCredentials(url, username, password string) error {

	creds := &Credentials{
		ServerURL: url,
		Username:  username,
		Secret:    password,
	}

	return CurrentHelper.Add(creds)
}

// SupportsStorage will return true or false if storage is supported.
func SupportsStorage() bool {
	return CurrentHelper.SupportsCredentialStorage()
}
