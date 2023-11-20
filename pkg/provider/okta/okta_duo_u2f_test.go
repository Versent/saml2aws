package okta

import (
	"testing"

	"github.com/marshallbrekka/go-u2fhost"
	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/mocks"
)

func TestChallengeDuoU2F(t *testing.T) {
	challengeNonce := "challengeNonce"
	appID := "appID"
	version := "version"
	keyHandle := "keyHandle"
	stateToken := "stateToken"

	request := &u2fhost.AuthenticateRequest{
		Challenge: challengeNonce,
		Facet:     appID,
		AppId:     appID,
		KeyHandle: keyHandle,
		WebAuthn:  false,
	}

	clientData := "exampleClientDat"
	signatureData := "exampleSignatureData"

	response := &u2fhost.AuthenticateResponse{
		ClientData:    clientData,
		SignatureData: signatureData,
	}

	device := &mocks.U2FDevice{}
	mockDeviceFinder := &MockDeviceFinder{device}
	device.On("Open").Return(nil)
	device.On("Close").Return(nil)

	client, err := NewDUOU2FClient(challengeNonce, appID, version, keyHandle, stateToken, mockDeviceFinder)
	assert.NoError(t, err)

	t.Run("error", func(t *testing.T) {
		device.On("Authenticate", request).Return(nil, &u2fhost.BadKeyHandleError{}).Once()

		resp, err := client.ChallengeU2F()
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, &u2fhost.BadKeyHandleError{})
	})

	t.Run("retry", func(t *testing.T) {
		device.On("Authenticate", request).Return(nil, &u2fhost.TestOfUserPresenceRequiredError{}).Once()
		device.On("Authenticate", request).Return(response, nil).Once()

		resp, err := client.ChallengeU2F()
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("success", func(t *testing.T) {
		device.On("Authenticate", request).Return(response, nil).Once()

		resp, err := client.ChallengeU2F()
		assert.NoError(t, err)
		assert.Equal(t, stateToken, resp.SessionId)
		assert.Equal(t, clientData, resp.ClientData)
		assert.Equal(t, signatureData, resp.SignatureData)
		assert.Equal(t, keyHandle, resp.KeyHandle)
	})
}
