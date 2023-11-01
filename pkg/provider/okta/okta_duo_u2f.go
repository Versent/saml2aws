package okta

import (
	"errors"
	"fmt"
	"time"

	"github.com/marshallbrekka/go-u2fhost"
)

// DUOU2fClient represents a challenge and the device used to respond
type DUOU2FClient struct {
	ChallengeNonce string
	AppID          string
	Version        string
	Device         u2fhost.Device
	KeyHandle      string
	StateToken     string
}

// ResponseData is passed back to DUO as a response
type ResponseData struct {
	SessionId     string `json:"sessionId"`
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
	KeyHandle     string `json:"keyHandle"`
}

// NewDUOU2FClient returns a new initialized DUOU2F-based WebAuthnClient, representing a single device
func NewDUOU2FClient(challengeNonce, appID, version, keyHandle, stateToken string, deviceFinder DeviceFinder) (*DUOU2FClient, error) {
	var device u2fhost.Device
	var err error

	retryCount := 0
	for retryCount < MaxOpenRetries {
		device, err = deviceFinder.findDevice()
		if err != nil {
			if err == errNoDeviceFound {
				return nil, err
			}

			retryCount++
			time.Sleep(RetryDelayMS)
			continue
		}

		return &DUOU2FClient{
			Device:         device,
			ChallengeNonce: challengeNonce,
			AppID:          appID,
			Version:        version,
			KeyHandle:      keyHandle,
			StateToken:     stateToken,
		}, nil
	}

	return nil, fmt.Errorf("failed to create client: %s. exceeded max retries of %d", err, MaxOpenRetries)
}

// ChallengeU2F takes a FidoClient and returns a signed assertion to send to Okta
func (d *DUOU2FClient) ChallengeU2F() (*ResponseData, error) {
	if d.Device == nil {
		return nil, errors.New("No Device Found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: d.ChallengeNonce,
		Facet:     d.AppID,
		AppId:     d.AppID,
		KeyHandle: d.KeyHandle,
		WebAuthn:  false,
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	var responsePayload *ResponseData

	defer func() {
		d.Device.Close()
	}()
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return nil, errors.New("Failed to get authentication response after 25 seconds")
		case <-interval.C:
			response, err := d.Device.Authenticate(request)
			if err == nil {
				responsePayload = &ResponseData{
					SessionId:     d.StateToken,
					ClientData:    response.ClientData,
					SignatureData: response.SignatureData,
					KeyHandle:     d.KeyHandle,
				}
				fmt.Printf("  ==> Touch accepted. Proceeding with authentication\n")
				return responsePayload, nil
			}

			switch err.(type) {
			case *u2fhost.TestOfUserPresenceRequiredError:
				if !prompted {
					fmt.Printf("\nTouch the flashing U2F device to authenticate...\n")
					prompted = true
				}
			default:
				return responsePayload, err
			}
		}
	}
}
