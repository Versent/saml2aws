package credentials

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

type MockHelper struct {
	Credentials     map[string]*Credentials
	AddFailError    error
	DeleteFailError error
}

func NewMockHelper() *MockHelper {
	return &MockHelper{
		Credentials: make(map[string]*Credentials),
	}
}

func (m *MockHelper) Add(c *Credentials) error {
	if m.AddFailError != nil {
		return m.AddFailError
	}
	m.Credentials[GetKeyFromAccount(c.IdpName)] = c
	return nil
}

func (m *MockHelper) Delete(keyname string) error {
	if m.DeleteFailError != nil {
		return m.DeleteFailError
	}
	if _, ok := m.Credentials[keyname]; !ok {
		return fmt.Errorf("%s not found in credential set (keychain mock)", keyname)
	}
	delete(m.Credentials, keyname)
	return nil
}

func (m *MockHelper) Get(keyName string) (string, string, error) {
	if _, ok := m.Credentials[keyName]; !ok {
		return "", "", fmt.Errorf("%s not found in credential set (keychain mock)", keyName)
	}
	return m.Credentials[keyName].Username, m.Credentials[keyName].Secret, nil
}

func (m *MockHelper) LegacyGet(serverURL string) (string, string, error) {
	return m.Get(serverURL)
}

func (m *MockHelper) SupportsCredentialStorage() bool {
	return true
}

func TestLookupCredentials(t *testing.T) {
	oldHelper := CurrentHelper

	testCases := []struct {
		CaseName             string
		initialCredentials   map[string]*Credentials
		loginDetails         creds.LoginDetails
		expectedError        bool
		expectedUsername     string
		expectedPassword     string
		expectedOktaCookie   string
		expectedClientID     string
		expectedClientSecret string
	}{
		{
			CaseName: "CredentialsFound",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "ADFS",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"saml2aws_credentials_test": {
					Username: "user1",
					Secret:   "password1",
				},
			},
			expectedUsername: "user1",
			expectedPassword: "password1",
		},
		{
			CaseName: "CredentialsNotFound",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "ADFS",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{},
			expectedError:      true,
		},
		{
			CaseName: "CredentialsFoundButFallBack",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "ADFS",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"https://someurl.com/": {
					Username: "user1",
					Secret:   "password1",
				},
			},
			expectedUsername: "user1",
			expectedPassword: "password1",
		},
		// for Okta
		{
			CaseName: "CredentialsWorkForOkta",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "Okta",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"saml2aws_credentials_test": {
					Username: "user1",
					Secret:   "password1",
				},
				"saml2aws_credentials_test_okta_session": {
					Secret: "cookie1",
				},
			},
			expectedUsername:   "user1",
			expectedPassword:   "password1",
			expectedOktaCookie: "cookie1",
		},
		{
			CaseName: "CredentialsFallbackWorkForOkta",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "Okta",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"https://someurl.com/": {
					Username: "user2",
					Secret:   "password2",
				},
				"https://someurl.com//sessionCookie": {
					Secret: "cookie2",
				},
			},
			expectedUsername:   "user2",
			expectedPassword:   "password2",
			expectedOktaCookie: "cookie2",
		},
		{
			CaseName: "CredentialsWorkForOktaButCookieFails",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "Okta",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"saml2aws_credentials_test": {
					Username: "user3",
					Secret:   "password3",
				},
			},
			expectedUsername:   "user3",
			expectedPassword:   "password3",
			expectedOktaCookie: "",
			expectedError:      false,
		},

		// For OneLogin
		{
			CaseName: "CredentialsWorkForOneLogin",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "OneLogin",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"saml2aws_credentials_test": {
					Username: "user4",
					Secret:   "password4",
				},
				"saml2aws_credentials_test_onelogin_token": {
					Username: "clientId1",
					Secret:   "clientSecret1",
				},
			},
			expectedUsername:     "user4",
			expectedPassword:     "password4",
			expectedClientID:     "clientId1",
			expectedClientSecret: "clientSecret1",
		},
		{
			CaseName: "CredentialsWorksButFailForOneLoginToken",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "OneLogin",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"saml2aws_credentials_test": {
					Username: "user5",
					Secret:   "password5",
				},
			},
			expectedError: true,
		},
		{
			CaseName: "CredentialsFallbackWorkForOneLogin",
			loginDetails: creds.LoginDetails{
				IdpName:     "test",
				IdpProvider: "OneLogin",
				URL:         "https://someurl.com/",
			},
			initialCredentials: map[string]*Credentials{
				"https://someurl.com/": {
					Username: "user6",
					Secret:   "password6",
				},
				"https:/someurl.com/auth/oauth2/v2/token": {
					Username: "clientId2",
					Secret:   "clientSecret2",
				},
			},
			expectedUsername:     "user6",
			expectedPassword:     "password6",
			expectedClientID:     "clientId2",
			expectedClientSecret: "clientSecret2",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.CaseName, func(t *testing.T) {
			t.Log(testCase.CaseName)
			m := NewMockHelper()
			CurrentHelper = m
			m.Credentials = testCase.initialCredentials
			t.Log(testCase.initialCredentials)
			err := LookupCredentials(&testCase.loginDetails)
			if testCase.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.EqualValues(t, testCase.expectedUsername, testCase.loginDetails.Username)
				assert.EqualValues(t, testCase.expectedPassword, testCase.loginDetails.Password)
				assert.EqualValues(t, testCase.expectedOktaCookie, testCase.loginDetails.OktaSessionCookie)
				assert.EqualValues(t, testCase.expectedClientID, testCase.loginDetails.ClientID)
				assert.EqualValues(t, testCase.expectedClientSecret, testCase.loginDetails.ClientSecret)
			}
		})
	}

	// restoring the old Helper
	CurrentHelper = oldHelper
}

func TestSaveCredentials(t *testing.T) {
	oldHelper := CurrentHelper

	testCases := []struct {
		CaseName                  string
		IdpName                   string
		URL                       string
		Username                  string
		Password                  string
		expectedCredentialKeyName string
		expectedError             bool
	}{
		{
			CaseName:                  "SaveCredentials",
			IdpName:                   "test",
			URL:                       "http://test.com/",
			Username:                  "user1",
			Password:                  "password1",
			expectedCredentialKeyName: "saml2aws_credentials_test",
		},
		{
			CaseName:      "EmptyIdpNameRaisesError",
			IdpName:       "",
			URL:           "http://test.com/",
			Username:      "user2",
			Password:      "password2",
			expectedError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.CaseName, func(t *testing.T) {
			m := NewMockHelper()
			CurrentHelper = m
			err := SaveCredentials(testCase.IdpName, testCase.URL, testCase.Username, testCase.Password)
			if testCase.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				_, ok := m.Credentials[testCase.expectedCredentialKeyName]
				assert.True(t, ok)
				assert.EqualValues(t, testCase.Username, m.Credentials[testCase.expectedCredentialKeyName].Username)
				assert.EqualValues(t, testCase.Password, m.Credentials[testCase.expectedCredentialKeyName].Secret)
			}
		})
	}

	// restoring the old Helper
	CurrentHelper = oldHelper
}
