package keyring

import (
	"encoding/json"
	"fmt"

	"github.com/versent/saml2aws/pkg/prompter"

	. "github.com/99designs/keyring"
	"github.com/versent/saml2aws/helper/credentials"
)

type KeyringHelper struct {
	keyring Keyring
}

func terminalPrompt(prompt string) (string, error) {
	return prompter.Password(prompt), nil
}

func NewKeyringHelper() (*KeyringHelper, error) {
	kr, err := Open(Config{
		KeychainTrustApplication: true,
		LibSecretCollectionName:  "login",
		FileDir:                  "~/.aws/saml2aws/",
		FilePasswordFunc:         terminalPrompt,
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

	return kr.keyring.Set(Item{
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
		return "", "", credentials.ErrCredentialsNotFound
	}
	var creds credentials.Credentials
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		fmt.Println(err)
		return "", "", credentials.ErrCredentialsNotFound
	}

	return creds.Username, creds.Secret, nil
}

func (KeyringHelper) SupportsCredentialStorage() bool {
	return true
}
