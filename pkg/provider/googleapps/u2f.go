package googleapps

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
)

const (
	maxOpenRetries = 10
	retryDelay     = 200 * time.Millisecond
)

var (
	errNoDeviceFound = fmt.Errorf("no U2F devices found. device might not be plugged in")
)

// U2FClient represents a challenge and the device used to respond
type U2FClient struct {
	ChallengeNonce string
	AppID          string
	Facet          string
	Device         u2fhost.Device
	KeyHandle      string
}

// DeviceFinder is used to mock out finding devices
type DeviceFinder interface {
	findDevice() (u2fhost.Device, error)
}

// U2FDevice is used to support mocking this device with mockery https://github.com/vektra/mockery/issues/210#issuecomment-485026348
type U2FDevice interface {
	u2fhost.Device
}

// NewU2FClient returns a new initialized FIDO1-based U2F client, representing a single device
func NewU2FClient(challengeNonce, appID, facet, keyHandle string, deviceFinder DeviceFinder) (*U2FClient, error) {
	var device u2fhost.Device
	var err error

	retryCount := 0
	for retryCount < maxOpenRetries {
		device, err = deviceFinder.findDevice()
		if err != nil {
			if err == errNoDeviceFound {
				return nil, err
			}

			retryCount++
			time.Sleep(retryDelay)
			continue
		}

		return &U2FClient{
			Device:         device,
			ChallengeNonce: challengeNonce,
			AppID:          appID,
			KeyHandle:      keyHandle,
			Facet:          facet,
		}, nil
	}

	return nil, fmt.Errorf("failed to create client: %s. exceeded max retries of %d", err, maxOpenRetries)
}

// ChallengeU2F takes a U2FClient and returns a signed assertion to send to Google
func (d *U2FClient) ChallengeU2F() (string, error) {
	if d.Device == nil {
		return "", errors.New("No Device Found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: b64Safe(d.ChallengeNonce),
		Facet:     d.Facet,
		AppId:     d.AppID,
		KeyHandle: b64Safe(d.KeyHandle),
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)

	d.Device.Open()
	defer func() {
		d.Device.Close()
	}()

	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return "", errors.New("Failed to get authentication response after 25 seconds")
		case <-interval.C:
			response, err := d.Device.Authenticate(request)
			if err == nil {
				responseJSON, err := json.Marshal(response)
				if err != nil {
					return "", err
				}
				fmt.Printf("  ==> Touch accepted. Proceeding with authentication\n")
				return string(responseJSON), nil
			}

			switch err.(type) {
			case *u2fhost.TestOfUserPresenceRequiredError:
				if !prompted {
					fmt.Printf("\nTouch the flashing U2F device to authenticate...\n")
					prompted = true
				}
			default:
				return "", err
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

func b64Safe(data string) string {
	val, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(val)
}
