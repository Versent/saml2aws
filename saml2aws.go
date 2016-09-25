package saml2aws

//go:generate stringer -type=Provider

import "fmt"

type Provider int

const (
	ADFS Provider = iota
	Ping
)

// SAMLClient client interface
type SAMLClient interface {
	Authenticate(loginDetails *LoginDetails) (string, error)
}

type SAMLOptions struct {
	SkipVerify bool
	Provider   string
}

// NewSAMLClient create a new SAML client
func NewSAMLClient(opts *SAMLOptions) (SAMLClient, error) {
	switch opts.Provider {
	case ADFS.String():
		return NewADFSClient(opts.SkipVerify)
	case Ping.String():
		return NewPingFedClient(opts.SkipVerify)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", opts.Provider)
	}
}
