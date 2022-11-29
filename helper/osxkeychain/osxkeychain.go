// +build darwin

package osxkeychain

import (
	"github.com/keybase/go-keychain"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/helper/credentials"
)

var logger = logrus.WithField("helper", "osxkeychain")

// Osxkeychain handles secrets using the OS X Keychain as store.
type Osxkeychain struct{}

// Add adds new credentials to the keychain.
func (h Osxkeychain) Add(creds *credentials.Credentials) error {
	err := h.Delete(creds.ServerURL)
	if err != nil {
		logger.WithError(err).Debug("delete of existing keychain entry failed")
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetLabel(credentials.CredsLabel)
	item.SetAccount(creds.Username)
	item.SetData([]byte(creds.Secret))
	item.SetService(creds.ServerURL)

	err = keychain.AddItem(item)
	if err != nil {
		// TODO: look into updates using keychain.ErrorDuplicateItem
		return err
	}

	return nil
}

// Delete removes credentials from the keychain.
func (h Osxkeychain) Delete(serverURL string) error {

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(serverURL)
	err := keychain.DeleteItem(item)
	if err != nil {
		return err
	}

	return nil
}

// Get returns the username and secret to use for a given registry server URL.
func (h Osxkeychain) Get(serverURL string) (string, string, error) {

	logger.WithField("serverURL", serverURL).Debug("Get credentials")

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(serverURL)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", "", err
	}

	if len(results) == 0 {
		return "", "", credentials.ErrCredentialsNotFound
	}

	logger.WithField("user", results[0].Account).Debug("Get credentials")

	return results[0].Account, string(results[0].Data), nil
}

// SupportsCredentialStorage returns true since storage is supported
func (Osxkeychain) SupportsCredentialStorage() bool {
	return true
}
