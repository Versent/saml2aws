package saml2aws

import (
	"fmt"
	"sort"

	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider/adfs"
	"github.com/versent/saml2aws/pkg/provider/adfs2"
	"github.com/versent/saml2aws/pkg/provider/jumpcloud"
	"github.com/versent/saml2aws/pkg/provider/keycloak"
	"github.com/versent/saml2aws/pkg/provider/okta"
	"github.com/versent/saml2aws/pkg/provider/pingfed"
)

// ProviderList list of providers with their MFAs
type ProviderList map[string][]string

// MFAsByProvider a list of providers with their respective supported MFAs
var MFAsByProvider = ProviderList{
	"ADFS":      []string{"Auto", "VIP"},
	"ADFS2":     []string{"Auto"},
	"Ping":      []string{"Auto"}, // automatically detects PingID
	"JumpCloud": []string{"Auto"},
	"Okta":      []string{"Auto"}, // automatically detects DUO, SMS and ToTP
	"KeyCloak":  []string{"Auto"}, // automatically detects ToTP
}

// Names get a list of provider names
func (mfbp ProviderList) Names() []string {
	keys := []string{}
	for k := range mfbp {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

// Mfas retrieve a sorted list of mfas from the provider list
func (mfbp ProviderList) Mfas(provider string) []string {
	mfas := mfbp[provider]

	sort.Strings(mfas)

	return mfas
}

func (mfbp ProviderList) stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func invalidMFA(provider string, mfa string) bool {
	supportedMfas := MFAsByProvider.Mfas(provider)
	supported := MFAsByProvider.stringInSlice(mfa, supportedMfas)
	if supported {
		return false
	}
	return true
}

// SAMLClient client interface
type SAMLClient interface {
	Authenticate(loginDetails *creds.LoginDetails) (string, error)
}

// NewSAMLClient create a new SAML client
func NewSAMLClient(idpAccount *cfg.IDPAccount) (SAMLClient, error) {
	switch idpAccount.Provider {
	case "ADFS":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return adfs.New(idpAccount)
	case "ADFS2":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return adfs2.New(idpAccount)
	case "Ping":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return pingfed.New(idpAccount)
	case "JumpCloud":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return jumpcloud.New(idpAccount)
	case "Okta":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return okta.New(idpAccount)
	case "KeyCloak":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return keycloak.New(idpAccount)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", idpAccount.Provider)
	}
}
