package credentials

import (
	"errors"
)

var (
	// CurrentHelper the currently configured credentials helper
	CurrentHelper Helper = &defaultHelper{}

	// ErrCredentialsNotFound returned when the credential can't be located in the native store.
	ErrCredentialsNotFound = errors.New("credentials not found in native keychain")
)

// Credentials holds the information shared between gossamer3 and the credentials store.
type Credentials struct {
	ServerURL string
	Username  string
	Secret    string
}

// CredsLabel gossamer3 credentials should be labeled as such in credentials stores that allow labelling.
// That label allows to filter out non-Docker credentials too at lookup/search in macOS keychain,
// Windows credentials manager and Linux libsecret. Default value is "gossamer3 Credentials"
var CredsLabel = "gossamer3 Credentials"

// Helper is the interface a credentials store helper must implement.
type Helper interface {
	// Add appends credentials to the store.
	Add(*Credentials) error
	// Delete removes credentials from the store.
	Delete(serverURL string) error
	// Get retrieves credentials from the store.
	// It returns username and secret as strings.
	Get(serverURL string) (string, string, error)
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
