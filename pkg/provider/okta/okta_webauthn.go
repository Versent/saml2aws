package okta

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marshallbrekka/go-u2fhost"
)

const (
	MaxOpenRetries = 10
	RetryDelayMS   = 200 * time.Millisecond
)

var (
	errNoDeviceFound = fmt.Errorf("no U2F devices found. device might not be plugged in")
)

// FidoClient represents a challenge and the device used to respond
type FidoClient struct {
	ChallengeNonce string
	AppID          string
	Version        string
	Device         u2fhost.Device
	KeyHandle      string
	StateToken     string
}

// SignedAssertion is passed back to Okta as response
type SignedAssertion struct {
	StateToken        string `json:"stateToken"`
	ClientData        string `json:"clientData"`
	SignatureData     string `json:"signatureData"`
	AuthenticatorData string `json:"authenticatorData"`
}

// DeviceFinder is used to mock out finding devices
type DeviceFinder interface {
	findDevice() (u2fhost.Device, error)
}

// U2FDevice is used to support mocking this device with mockery https://github.com/vektra/mockery/issues/210#issuecomment-485026348
type U2FDevice interface {
	u2fhost.Device
}

// NewFidoClient returns a new initialized FIDO1-based WebAuthnClient, representing a single device
func NewFidoClient(challengeNonce, appID, version, keyHandle, stateToken string, deviceFinder DeviceFinder) (FidoClient, error) {
	var device u2fhost.Device
	var err error

	retryCount := 0
	for retryCount < MaxOpenRetries {
		device, err = deviceFinder.findDevice()
		if err != nil {
			if err == errNoDeviceFound {
				return FidoClient{}, err
			}

			retryCount++
			time.Sleep(RetryDelayMS)
			continue
		}

		return FidoClient{
			Device:         device,
			ChallengeNonce: challengeNonce,
			AppID:          appID,
			Version:        version,
			KeyHandle:      keyHandle,
			StateToken:     stateToken,
		}, nil
	}

	return FidoClient{}, fmt.Errorf("failed to create client: %s. exceeded max retries of %d", err, MaxOpenRetries)
}

// ChallengeU2F takes a FidoClient and returns a signed assertion to send to Okta
func (d *FidoClient) ChallengeU2F() (*SignedAssertion, error) {
	if d.Device == nil {
		return nil, errors.New("No Device Found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: d.ChallengeNonce,
		Facet:     "https://" + d.AppID,
		AppId:     d.AppID,
		KeyHandle: d.KeyHandle,
		WebAuthn:  true,
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	var responsePayload *SignedAssertion

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
				responsePayload = &SignedAssertion{
					StateToken:        d.StateToken,
					ClientData:        response.ClientData,
					SignatureData:     response.SignatureData,
					AuthenticatorData: response.AuthenticatorData,
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
				errString := fmt.Sprintf("%s", err)
				if strings.Contains(errString, "U2FHIDError") {
					fmt.Printf("Let's keep looping till times out. err: %s \n", err)
				} else if strings.Contains(errString, "hidapi: hid_error is not implemented yet") {
					fmt.Printf("Let's keep looping till times out. err: %s \n", err)
				/*} else if strings.Contains(errString, "The provided key handle is not present on the device"){
					fmt.Printf("Let's keep looping till times out. err: %s \n", err)*/
				} else {
					fmt.Printf("other errors? err: %s \n", err)
					return responsePayload, err
				}
			}
		}
	}

}

// U2FDeviceFinder returns a U2F device
type U2FDeviceFinder struct{}

func (*U2FDeviceFinder) findDevice() (u2fhost.Device, error) {
	var err error

	allDevices := u2fhost.Devices()
	if len(allDevices) == 0 {
		return nil, errNoDeviceFound
	}

	for i, device := range allDevices {
		err = device.Open()
		if err != nil {
			device.Close()

			continue
		}

		return allDevices[i], nil
	}

	return nil, fmt.Errorf("failed to open fido U2F device: %s", err)
}
