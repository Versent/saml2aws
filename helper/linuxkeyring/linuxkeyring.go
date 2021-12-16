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

func NewKeyringHelper(linuxKeyringName string) (*KeyringHelper, error) {
	// enable debug logging from 99designs/keyring when we have debug logging enabled
	logLevel := logrus.GetLevel()
	keyring.Debug = (logLevel == logrus.DebugLevel || logLevel == logrus.TraceLevel)

	var backends []keyring.BackendType

	switch linuxKeyringName {
	case "kwallet":
		backends = []keyring.BackendType{keyring.KWalletBackend}
	case "pass":
		backends = []keyring.BackendType{keyring.PassBackend}
	case "secret-service":
		backends = []keyring.BackendType{keyring.SecretServiceBackend}
	default:
		backends = []keyring.BackendType{
			keyring.KWalletBackend,
			keyring.SecretServiceBackend,
			keyring.PassBackend,
		}
	}

	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:         backends,
		LibSecretCollectionName: "login",
		PassPrefix:              "saml2aws",
	})

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
		Key:                         creds.ServerURL,
		Label:                       credentials.CredsLabel,
		Data:                        encoded,
		KeychainNotTrustApplication: false,
	})
}

func (kr *KeyringHelper) Delete(serverURL string) error {
	return kr.keyring.Remove(serverURL)
}

func (kr *KeyringHelper) Get(serverURL string) (string, string, error) {
	item, err := kr.keyring.Get(serverURL)
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

func (KeyringHelper) SupportsCredentialStorage() bool {
	return true
}
