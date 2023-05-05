package okta

import (
	"testing"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/mocks"
)

type fidoClientTests struct {
	title string
	err   error
}

type MockDeviceFinder struct {
	device *mocks.U2FDevice
}

func (m *MockDeviceFinder) findDevice() (u2fhost.Device, error) {
	return m.device, nil
}

func TestNewFidoClient(t *testing.T) {
	challengeNonce := "challengeNonce"
	appID := "appID"
	version := "version"
	keyHandle := "keyHandle"
	stateToken := "stateToken"
	tests := []fidoClientTests{
		{
			title: "Returns new client successfully if device found",
			err:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			_, err := NewFidoClient(challengeNonce, appID, version, keyHandle, stateToken, &MockDeviceFinder{&mocks.U2FDevice{}})
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

func TestChallengeWebAuthnU2F(t *testing.T) {
	challengeNonce := "challengeNonce"
	appID := "appID"
	version := "version"
	keyHandle := "keyHandle"
	stateToken := "stateToken"
	tests := []fidoClientTests{
		{
			title: "Returns signed assertion from device",
			err:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			device := &mocks.U2FDevice{}
			mockDeviceFinder := &MockDeviceFinder{device}
			device.On("Open").Return(nil)
			request := &u2fhost.AuthenticateRequest{
				Challenge:          challengeNonce,
				AppId:              appID,
				Facet:              appID,
				KeyHandle:          keyHandle,
				ChannelIdPublicKey: nil,
				ChannelIdUnused:    false,
				CheckOnly:          false,
				WebAuthn:           false,
			}
			response := &u2fhost.AuthenticateResponse{}
			device.On("Authenticate", request).Return(response, nil)
			device.On("Close").Return(nil)
			client, _ := NewFidoClient(challengeNonce, appID, version, keyHandle, stateToken, mockDeviceFinder)
			_, err := client.ChallengeU2F()
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
