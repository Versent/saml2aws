package credentials

import "fmt"

// LookupCredentials lookup an existing set of credentials and validate it.
func LookupCredentials(hostname string) (string, string, error) {

	username, password, err := CurrentHelper.Get(fmt.Sprintf("https://%s", hostname))

	return username, password, err
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
