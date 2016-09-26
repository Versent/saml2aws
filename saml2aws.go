package saml2aws

import "fmt"

// Provider the SAML provider
type Provider int

const (
	// ADFS 3.x provider
	ADFS Provider = iota
	// Ping provider
	Ping
)

// SAMLClient client interface
type SAMLClient interface {
	Authenticate(loginDetails *LoginDetails) (string, error)
}

// SAMLOptions options for the new SAML client
type SAMLOptions struct {
	SkipVerify bool
	Provider   string
}

// NewSAMLClient create a new SAML client
func NewSAMLClient(opts *SAMLOptions) (SAMLClient, error) {
	switch opts.Provider {
	case "ADFS":
		return NewADFSClient(opts.SkipVerify)
	case "Ping":
		return NewPingFedClient(opts.SkipVerify)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", opts.Provider)
	}
}
