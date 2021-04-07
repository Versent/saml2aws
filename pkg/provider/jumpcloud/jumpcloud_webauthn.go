package jumpcloud

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/marshallbrekka/go-u2fhost"
)

const (
	MaxOpenRetries = 10
	RetryDelayMS   = 200 * time.Millisecond

	jumpCloudOrigin = "https://console.jumpcloud.com"
)

var (
	errNoDeviceFound = fmt.Errorf("no U2F devices found. device might not be plugged in")
)

// FidoClient represents a challenge and the device used to respond
type FidoClient struct {
	challenge string
	rpId      string
	keyHandle string
	token     string

	Device u2fhost.Device
}

type JumpCloudResponse struct {
	PublicKeyCredential PublicKey `json:"publicKeyCredential"`
	Token               string    `json:"token"`
}

type PublicKey struct {
	Id       string            `json:"id"`
	RawId    string            `json:"rawId"`
	Type     string            `json:"type"`
	Response PublicKeyResponse `json:"response"`
}

type PublicKeyResponse struct {
	ClientData        string  `json:"clientDataJSON"`
	AuthenticatorData string  `json:"authenticatorData"`
	SignatureData     string  `json:"signature"`
	UserHandle        *string `json:"userHandle"`
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
func NewFidoClient(challenge, rpId, keyHandle, token string, deviceFinder DeviceFinder) (FidoClient, error) {
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
			Device:    device,
			challenge: challenge,
			rpId:      rpId,
			keyHandle: keyHandle,
			token:     token,
		}, nil
	}

	return FidoClient{}, fmt.Errorf("failed to create client: %s. exceeded max retries of %d", err, MaxOpenRetries)
}

// ChallengeU2F takes a FidoClient and returns a signed assertion to send to Okta
func (d *FidoClient) ChallengeU2F() (*JumpCloudResponse, error) {
	if d.Device == nil {
		return nil, errors.New("No Device Found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: d.challenge,
		Facet:     jumpCloudOrigin,
		AppId:     d.rpId,
		KeyHandle: d.keyHandle,
		WebAuthn:  true,
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	var responsePayload *JumpCloudResponse

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
				authenticatorData, err := urlEncode(response.AuthenticatorData)
				if err != nil {
					return nil, err
				}
				signatureData, err := urlEncode(response.SignatureData)
				if err != nil {
					return nil, err
				}
				responsePayload = &JumpCloudResponse{
					PublicKeyCredential: PublicKey{
						Id:    response.KeyHandle,
						RawId: response.KeyHandle,
						Type:  "public-key",
						Response: PublicKeyResponse{
							ClientData:        response.ClientData,
							AuthenticatorData: authenticatorData,
							SignatureData:     signatureData,
							UserHandle:        nil,
						},
					},
					Token: d.token,
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

func urlEncode(stdEncodedStr string) (string, error) {
	decodedStr, err := base64.StdEncoding.DecodeString(stdEncodedStr)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(decodedStr), nil
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
