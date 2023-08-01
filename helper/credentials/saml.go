package credentials

import (
	"path"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

// LookupCredentials lookup an existing set of credentials and validate it.
func LookupCredentials(loginDetails *creds.LoginDetails) error {
	var username, password string
	var err error

	username, password, err = CurrentHelper.Get(GetKeyFromAccount(loginDetails.IdpName))
	if err != nil {
		// the credential keyname has changed from server URL to Identity Provider (#762)
		// Falling back to old key name to preserve backward compatibility
		username, password, err = CurrentHelper.Get(loginDetails.URL)
		if err != nil {
			return err
		}
	}

	loginDetails.Username = username
	loginDetails.Password = password

	// If the provider is Okta, check for existing Okta Session Cookie (sid)
	if loginDetails.IdpProvider == "Okta" {
		// load up the Okta token from a different secret (idp name + Okta suffix)
		var oktaSessionCookie string
		var err error

		_, oktaSessionCookie, err = CurrentHelper.Get(GetKeyFromAccount(loginDetails.IdpName + OktaSessionCookieSuffix))
		if err != nil {
			// the credential keyname has changed from server URL to Identity Provider (#762)
			// Falling back to old key name to preserve backward compatibility
			_, oktaSessionCookie, _ = CurrentHelper.Get(loginDetails.URL + "/sessionCookie")
		}
		loginDetails.OktaSessionCookie = oktaSessionCookie
	}

	if loginDetails.IdpProvider == "OneLogin" {
		var id, secret string
		var err error
		// load up the one login token from a different secret (idp name + one login suffix)
		id, secret, err = CurrentHelper.Get(GetKeyFromAccount(loginDetails.IdpName + OneLoginTokenSuffix))
		if err != nil {
			// the credential keyname has changed from server URL to Identity Provider (#762)
			// Falling back to old key name to preserve backward compatibility
			id, secret, err = CurrentHelper.Get(path.Join(loginDetails.URL, "/auth/oauth2/v2/token"))
			if err != nil {
				return err
			}
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
