//go:build darwin && cgo
// +build darwin,cgo

package osxkeychain

import (
	"net/url"
	"strings"

	"github.com/keybase/go-keychain"
	"github.com/sirupsen/logrus"

	"github.com/versent/saml2aws/v2/helper/credentials"
)

var logger = logrus.WithField("helper", "osxkeychain")

// Osxkeychain handles secrets using the OS X Keychain as store.
type Osxkeychain struct{}

// Add adds new credentials to the keychain.
func (h Osxkeychain) Add(creds *credentials.Credentials) error {
	err := h.Delete(creds.IdpName)
	if err != nil {
		logger.WithError(err).Debug("delete of existing keychain entry failed")
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	item.SetLabel(credentials.GetKeyFromAccount(creds.IdpName))
	item.SetString("Purpose", credentials.CredsLabel)
	item.SetAccount(creds.Username)
	item.SetData([]byte(creds.Secret))
	err = splitServer3(creds.ServerURL, item)
	if err != nil {
		return err
	}

	err = keychain.AddItem(item)
	if err != nil {
		// TODO: look into updates using keychain.ErrorDuplicateItem
		return err
	}

	return nil
}

// Delete removes credentials from the keychain.
func (h Osxkeychain) Delete(keyName string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	item.SetLabel(keyName)
	return keychain.DeleteItem(item)
}

// Get returns the username and secret to use for a given registry server URL.
func (h Osxkeychain) Get(keyName string) (string, string, error) {
	logger.WithField("Credential Key", keyName).Debug("Get credentials")

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassInternetPassword)

	// only search on the idp name
	query.SetLabel(keyName)
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

func splitServer3(serverURL string, item keychain.Item) (err error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return
	}

	hostAndPort := strings.Split(u.Host, ":")
	SetServer(item, hostAndPort[0])
	if len(hostAndPort) == 2 {
		SetPort(item, hostAndPort[1])
	}

	SetProtocol(item, u.Scheme)
	SetPath(item, u.Path)

	return
}
