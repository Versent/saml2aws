package credentials

import (
	"errors"
	"fmt"
)

var (
	// CurrentHelper the currently configured credentials helper
	CurrentHelper Helper = &defaultHelper{}

	// ErrCredentialsNotFound returned when the credential can't be located in the native store.
	ErrCredentialsNotFound = errors.New("credentials not found in native keychain")
)

// Credentials holds the information shared between saml2aws and the credentials store.
type Credentials struct {
	IdpName   string
	ServerURL string
	Username  string
	Secret    string
}

const (
	// CredsLabel saml2aws credentials should be labeled as such in credentials stores that allow labelling.
	// That label allows to filter out non-Docker credentials too at lookup/search in macOS keychain,
	// Windows credentials manager and Linux libsecret. Default value is "saml2aws Credentials"
	CredsLabel              = "saml2aws Credentials"
	CredsKeyPrefix          = "saml2aws_credentials"
	OktaSessionCookieSuffix = "_okta_session"
	OneLoginTokenSuffix     = "_onelogin_token"
)

func GetKeyFromAccount(accountName string) string {
	return fmt.Sprintf("%s_%s", CredsKeyPrefix, accountName)
}

// Helper is the interface a credentials store helper must implement.
type Helper interface {
	// Add appends credentials to the store.
	Add(*Credentials) error
	// Delete removes credentials from the store.
	Delete(idpName string) error
	// Get retrieves credentials from the store.
	// It returns username and secret as strings.
	Get(idpName string) (string, string, error)
	// SupportsCredentialStorage returns true or false if there is credential storage.
	SupportsCredentialStorage() bool
}

// IsErrCredentialsNotFound returns true if the error
// was caused by not having a set of credentials in a store.
func IsErrCredentialsNotFound(err error) bool {
	return err == ErrCredentialsNotFound
}

type defaultHelper struct{}

func (defaultHelper) Add(*Credentials) error {
	return nil
}

func (defaultHelper) Delete(serverURL string) error {
	return nil
}

func (defaultHelper) Get(serverURL string) (string, string, error) {
	return "", "", ErrCredentialsNotFound
}

func (defaultHelper) SupportsCredentialStorage() bool {
	return false
}
