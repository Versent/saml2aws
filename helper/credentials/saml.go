package credentials

import (
	"github.com/versent/saml2aws/v2/pkg/creds"
)

// LookupCredentials lookup an existing set of credentials and validate it.
func LookupCredentials(loginDetails *creds.LoginDetails) error {

	username, password, err := CurrentHelper.Get(loginDetails.IdpName)
	if err != nil {
		return err
	}

	loginDetails.Username = username
	loginDetails.Password = password

	// If the provider is Okta, check for existing Okta Session Cookie (sid)
	if loginDetails.IdpProvider == "Okta" {
		// load up the Okta token from a different secret (idp name + Okta suffix)
		_, oktaSessionCookie, err := CurrentHelper.Get(loginDetails.IdpName + OktaSessionCookieSuffix)
		if err == nil {
			loginDetails.OktaSessionCookie = oktaSessionCookie
		}
	}

	if loginDetails.IdpProvider == "OneLogin" {
		// load up the one login token from a different secret (idp name + one login suffix)
		id, secret, err := CurrentHelper.Get(loginDetails.IdpName + OneLoginTokenSuffix)
		if err != nil {
			return err
		}
		loginDetails.ClientID = id
		loginDetails.ClientSecret = secret
	}
	return nil
}

// SaveCredentials save the user credentials.
func SaveCredentials(idpName, url, username, password string) error {

	creds := &Credentials{
		IdpName:   idpName,
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
