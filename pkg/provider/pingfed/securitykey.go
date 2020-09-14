package pingfed

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"

	"github.com/marshallbrekka/go-u2fhost"
	"github.com/sirupsen/logrus"
)

type credentialInput struct {
	Type string  `json:"type"`
	ID   []int64 `json:"id"`
}

type parsedCredential struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type requestInput struct {
	Challenge        []int64           `json:"challenge"`
	Timeout          int64             `json:"timeout"`
	RpId             string            `json:"rpId"`
	AllowCredentials []credentialInput `json:"allowCredentials"`
	UserVerification string            `json:"userVerification"`
}

type parsedRequest struct {
	Challenge        string             `json:"challenge"`
	Timeout          int64              `json:"timeout"`
	RpId             string             `json:"rpId"`
	AllowCredentials []parsedCredential `json:"allowCredentials"`
	UserVerification string             `json:"userVerification"`
}

type securityKeyResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

type securityKeyOutput struct {
	ID       string              `json:"id"`
	RawID    string              `json:"rawId"`
	Type     string              `json:"type"`
	Response securityKeyResponse `json:"response"`
}

// securityKeyAuth : Perform authentication against security keys
func securityKeyAuth(publicKeyOptions string) (string, error) {
	logrus.Debugf("Public key options: %+v\n", publicKeyOptions)

	// Unmarshal the request
	var request requestInput
	if err := json.Unmarshal([]byte(publicKeyOptions), &request); err != nil {
		return "", errors.Wrap(err, "failed to unmarshal public key options")
	}

	// Check for credentials
	if len(request.AllowCredentials) == 0 {
		return "", errors.New("no credentials are registered with this IdP")
	}

	// Process the request
	parsedReq := processRequest(request)
	logrus.Debugf("Auth Request: %+v\n", parsedReq)

	// Prefix the origin when this is pingone.com
	origin := parsedReq.RpId
	if origin == "pingone.com" {
		origin = "https://authenticator.pingone.com"
	}

	// Look for devices
	allDevices := u2fhost.Devices()
	var openDevices []u2fhost.Device
	for _, device := range allDevices {
		if err := device.Open(); err == nil {
			openDevices = append(openDevices, device)
			defer func() {
				device.Close()
			}()
		}
	}

	// Check that devices were found
	if len(openDevices) == 0 {
		return "", errors.New("no U2F devices found")
	}

	// Perform authentication
	authReq := &u2fhost.AuthenticateRequest{
		Challenge: parsedReq.Challenge,
		AppId:     parsedReq.RpId,
		Facet:     origin,
		KeyHandle: parsedReq.AllowCredentials[0].ID,
		WebAuthn:  true,
	}
	authResp, err := authenticate(openDevices, authReq)
	if err != nil {
		return "", err
	}

	// Get the raw id
	rawID := base64.StdEncoding.EncodeToString(toByteArray(request.AllowCredentials[0].ID))

	// Generate the output
	output := securityKeyOutput{
		ID:    authReq.KeyHandle,
		RawID: rawID,
		Type:  "public-key",
		Response: securityKeyResponse{
			ClientDataJSON:    authResp.ClientData,
			AuthenticatorData: authResp.AuthenticatorData,
			Signature:         authResp.SignatureData,
		},
	}

	// Marshal to JSON
	bs, err := json.Marshal(output)
	if err != nil {
		return "", err
	}

	return string(bs), nil
}

// authenticate : Send authentication request to all open devices and return the first one that is successful
func authenticate(openDevices []u2fhost.Device, req *u2fhost.AuthenticateRequest) (*u2fhost.AuthenticateResponse, error) {
	timeout := time.After(time.Second * 20)
	interval := time.NewTicker(time.Millisecond * 250)
	prompted := false
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return nil, errors.New("authentication timed out after 20 seconds")
		case <-interval.C:
			for _, device := range openDevices {
				// Send authentication request
				response, err := device.Authenticate(req)

				if err == nil {
					// Success
					log.Println("U2F device authenticated")
					return response, nil
				} else if _, ok := err.(*u2fhost.TestOfUserPresenceRequiredError); ok {
					// Waiting for user to touch the device
					if !prompted {
						fmt.Println("Touch the flashing U2F device to authenticate...")
						prompted = true
					}
				} else {
					// Encountered an error
					return nil, err
				}
			}
		}
	}
}

// Convert an int array into a byte array
func toByteArray(buf []int64) []byte {
	var output []byte
	for _, item := range buf {
		output = append(output, byte(0xff&item))
	}

	return output
}

// Convert an int array to a base64 string
func toBase64Str(buf []int64) string {
	byteString := toByteArray(buf)
	return base64.RawURLEncoding.EncodeToString(byteString)
}

// Convert allowed credentials into base64 strings
func convertCredentials(creds []credentialInput) []parsedCredential {
	var output []parsedCredential

	for _, item := range creds {
		output = append(output, parsedCredential{
			ID:   toBase64Str(item.ID),
			Type: item.Type,
		})
	}

	return output
}

// process an authentication request
func processRequest(req requestInput) parsedRequest {
	return parsedRequest{
		Challenge:        toBase64Str(req.Challenge),
		Timeout:          req.Timeout,
		RpId:             req.RpId,
		AllowCredentials: convertCredentials(req.AllowCredentials),
		UserVerification: req.UserVerification,
	}
}
