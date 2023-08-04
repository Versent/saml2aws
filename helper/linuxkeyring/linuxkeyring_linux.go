package linuxkeyring

import (
	"encoding/json"

	"github.com/99designs/keyring"
	"github.com/sirupsen/logrus"

	"github.com/versent/saml2aws/v2/helper/credentials"
)

var logger = logrus.WithField("helper", "linuxkeyring")

type KeyringHelper struct {
	keyring keyring.Keyring
}

type Configuration struct {
	Backend string
}

func NewKeyringHelper(config Configuration) (*KeyringHelper, error) {
	c := keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.KWalletBackend,
			keyring.SecretServiceBackend,
			keyring.PassBackend,
		},
		LibSecretCollectionName: "login",
		PassPrefix:              "saml2aws",
	}

	// set the only allowed backend to be backend configured
	if config.Backend != "" {
		c.AllowedBackends = []keyring.BackendType{keyring.BackendType(config.Backend)}
	}

	kr, err := keyring.Open(c)
	if err != nil {
		return nil, err
	}

	return &KeyringHelper{
		keyring: kr,
	}, nil
}

func (kr *KeyringHelper) Add(creds *credentials.Credentials) error {
	encoded, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return kr.keyring.Set(keyring.Item{
		Key:                         credentials.GetKeyFromAccount(creds.IdpName),
		Label:                       credentials.CredsLabel,
		Data:                        encoded,
		KeychainNotTrustApplication: false,
	})
}

func (kr *KeyringHelper) Delete(keyName string) error {
	return kr.keyring.Remove(keyName)
}

func (kr *KeyringHelper) Get(keyName string) (string, string, error) {
	item, err := kr.keyring.Get(keyName)
	if err != nil {
		logger.WithField("err", err).Error("keychain Get returned error")
		return "", "", credentials.ErrCredentialsNotFound
	}
	var creds credentials.Credentials
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		logger.WithField("err", err).Error("stored credential malformed")
		return "", "", credentials.ErrCredentialsNotFound
	}

	return creds.Username, creds.Secret, nil
}

// this function is preserved for backward compatibility reasons
func (kr *KeyringHelper) LegacyGet(serverURL string) (string, string, error) {
	return kr.Get(serverURL)
}

func (KeyringHelper) SupportsCredentialStorage() bool {
	return true
}
