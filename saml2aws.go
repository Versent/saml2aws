package saml2aws

import (
	"fmt"

	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider/adfs"
	"github.com/versent/saml2aws/pkg/provider/adfs2"
	"github.com/versent/saml2aws/pkg/provider/jumpcloud"
	"github.com/versent/saml2aws/pkg/provider/keycloak"
	"github.com/versent/saml2aws/pkg/provider/okta"
	"github.com/versent/saml2aws/pkg/provider/pingfed"
)

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
	Authenticate(loginDetails *creds.LoginDetails) (string, error)
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
		return adfs.NewADFSClient(opts.SkipVerify)
	case "ADFS2":
		return adfs2.NewADFS2Client(opts.SkipVerify)
	case "Ping":
		return pingfed.NewPingFedClient(opts.SkipVerify)
	case "JumpCloud":
		return jumpcloud.NewJumpCloudClient(opts.SkipVerify)
	case "Okta":
		return okta.NewOktaClient(opts.SkipVerify)
	case "KeyCloak":
		return keycloak.NewKeyCloakClient(opts.SkipVerify)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", opts.Provider)
	}
}
