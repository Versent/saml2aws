package jumpcloud

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
	rpId := "rpId"
	keyHandle := "keyHandle"
	token := "token"
	tests := []fidoClientTests{
		{
			title: "Returns new client successfully if device found",
			err:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			_, err := NewFidoClient(challengeNonce, rpId, keyHandle, token, &MockDeviceFinder{&mocks.U2FDevice{}})
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}

func TestChallengeU2F(t *testing.T) {
	challengeNonce := "challengeNonce"
	rpId := "rpId"
	keyHandle := "keyHandle"
	token := "token"
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
				AppId:              rpId,
				Facet:              jumpCloudOrigin,
				KeyHandle:          keyHandle,
				ChannelIdPublicKey: nil,
				ChannelIdUnused:    false,
				CheckOnly:          false,
				WebAuthn:           true,
			}
			response := &u2fhost.AuthenticateResponse{}
			device.On("Authenticate", request).Return(response, nil)
			device.On("Close").Return(nil)
			client, _ := NewFidoClient(challengeNonce, rpId, keyHandle, token, mockDeviceFinder)
			_, err := client.ChallengeU2F()
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}
		})
	}
}
