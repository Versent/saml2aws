package gossamer3

import (
	"fmt"
	"sort"

	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/provider/pingfed"
	"github.com/GESkunkworks/gossamer3/pkg/provider/pingone"
)

// ProviderList list of providers with their MFAs
type ProviderList map[string][]string

// MFAsByProvider a list of providers with their respective supported MFAs
var MFAsByProvider = ProviderList{
	"Ping": []string{"Auto", "None"}, // automatically detects PingID
	//"PingOne": []string{"Auto"},         // automatically detects PingID
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
	return !MFAsByProvider.stringInSlice(mfa, supportedMfas)
}

// SAMLClient client interface
type SAMLClient interface {
	Authenticate(loginDetails *creds.LoginDetails) (string, error)
}

// NewSAMLClient create a new SAML client
func NewSAMLClient(idpAccount *cfg.IDPAccount) (SAMLClient, error) {
	switch idpAccount.Provider {
	case "Ping":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return pingfed.New(idpAccount)
	case "PingOne":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return pingone.New(idpAccount)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", idpAccount.Provider)
	}
}
