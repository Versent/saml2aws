package commands

import (
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/provider/onelogin"
)

// Store Credentials module
func TestStoreCredentialsOnDisabledKeychainFlagReturnsNil(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: true}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}

	result := storeCredentials(commonFlags, idpAccount, "password")

	assert.Nil(t, result)
}

func TestStoreCredentialsOnProvidedPasswordSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertCalled(t, "Add", creds)
	assert.Nil(t, result)
	credentials.CurrentHelper = oldCurrentHelper
}

func TestStoreCredentialsOnProvidedPasswordHandlesErrorOnSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(errors.New("i am an error")).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertCalled(t, "Add", creds)
	assert.ErrorContains(t, result, "i am an error")
	assert.ErrorContains(t, result, "error storing password in keychain")
	credentials.CurrentHelper = oldCurrentHelper
}

func TestStoreCredentialsOnMissingPasswordSkipsSavingCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: "Ping",
		Username: "wolfeidau",
	}
	creds := &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", creds).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "")

	helperMock.AssertNotCalled(t, "Add")
	assert.Nil(t, result)
	credentials.CurrentHelper = oldCurrentHelper
}

func TestStoreCredentialsOnMissingOneLoginClientIdExitsProgram(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", mock.Anything).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	if os.Getenv("BE_CRASHER") == "1" {
		storeCredentials(commonFlags, idpAccount, "password")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStoreCredentialsOnMissingOneLoginClientIdExitsProgram")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		credentials.CurrentHelper = oldCurrentHelper
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestStoreCredentialsOnMissingOneLoginClientSecretExitsProgram(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginSecret", ClientSecret: ""}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", mock.Anything).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	if os.Getenv("BE_CRASHER") == "1" {
		storeCredentials(commonFlags, idpAccount, "password")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestStoreCredentialsOnMissingOneLoginClientSecretExitsProgram")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		credentials.CurrentHelper = oldCurrentHelper
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestStoreCredentialsOnProvidedOneLoginSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginId", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}).Return(nil).Once()
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: path.Join("https://id.example.com", OneLoginOAuthPath), Username: "oneloginId", Secret: "oneloginSecret"}).Return(nil).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	helperMock.AssertNumberOfCalls(t, "Add", 2)
	assert.Nil(t, result)
	credentials.CurrentHelper = oldCurrentHelper
}

func TestStoreCredentialsOnProvidedOneLoginHandlesErrorOnSavesCredentials(t *testing.T) {
	commonFlags := &flags.CommonFlags{DisableKeychain: false, ClientID: "oneloginId", ClientSecret: "oneloginSecret"}
	idpAccount := &cfg.IDPAccount{
		URL:      "https://id.example.com",
		MFA:      "none",
		Provider: onelogin.ProviderName,
		Username: "wolfeidau",
	}
	helperMock := &mocks.Helper{}
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: "https://id.example.com", Username: "wolfeidau", Secret: "password"}).Return(nil).Once()
	helperMock.Mock.On("Add", &credentials.Credentials{ServerURL: path.Join("https://id.example.com", OneLoginOAuthPath), Username: "oneloginId", Secret: "oneloginSecret"}).Return(errors.New("failed again")).Once()
	oldCurrentHelper := credentials.CurrentHelper
	credentials.CurrentHelper = helperMock

	result := storeCredentials(commonFlags, idpAccount, "password")

	assert.ErrorContains(t, result, "failed again")
	assert.ErrorContains(t, result, "error storing client_id and client_secret in keychain")
	credentials.CurrentHelper = oldCurrentHelper
}
