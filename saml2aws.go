package saml2aws

import (
	"fmt"
	"sort"

	"github.com/versent/saml2aws/v2/pkg/provider/netiq"

	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/provider/aad"
	"github.com/versent/saml2aws/v2/pkg/provider/adfs"
	"github.com/versent/saml2aws/v2/pkg/provider/adfs2"
	"github.com/versent/saml2aws/v2/pkg/provider/akamai"
	"github.com/versent/saml2aws/v2/pkg/provider/f5apm"
	"github.com/versent/saml2aws/v2/pkg/provider/googleapps"
	"github.com/versent/saml2aws/v2/pkg/provider/jumpcloud"
	"github.com/versent/saml2aws/v2/pkg/provider/keycloak"
	"github.com/versent/saml2aws/v2/pkg/provider/okta"
	"github.com/versent/saml2aws/v2/pkg/provider/onelogin"
	"github.com/versent/saml2aws/v2/pkg/provider/pingfed"
	"github.com/versent/saml2aws/v2/pkg/provider/pingone"
	"github.com/versent/saml2aws/v2/pkg/provider/shell"
	"github.com/versent/saml2aws/v2/pkg/provider/shibboleth"
	"github.com/versent/saml2aws/v2/pkg/provider/shibbolethecp"
)

// ProviderList list of providers with their MFAs
type ProviderList map[string][]string

// MFAsByProvider a list of providers with their respective supported MFAs
var MFAsByProvider = ProviderList{
	"AzureAD":       []string{"Auto", "PhoneAppOTP", "PhoneAppNotification", "OneWaySMS"},
	"ADFS":          []string{"Auto", "VIP", "Azure", "Defender"},
	"ADFS2":         []string{"Auto", "RSA"}, // nothing automatic about ADFS 2.x
	"Ping":          []string{"Auto"},        // automatically detects PingID
	"PingOne":       []string{"Auto"},        // automatically detects PingID
	"JumpCloud":     []string{"Auto", "TOTP", "WEBAUTHN", "DUO"},
	"Okta":          []string{"Auto", "PUSH", "DUO", "SMS", "TOTP", "OKTA", "FIDO", "YUBICO TOKEN:HARDWARE"}, // automatically detects DUO, SMS, ToTP, and FIDO
	"OneLogin":      []string{"Auto", "OLP", "SMS", "TOTP", "YUBIKEY"},                                       // automatically detects OneLogin Protect, SMS and ToTP
	"KeyCloak":      []string{"Auto"},                                                                        // automatically detects ToTP
	"GoogleApps":    []string{"Auto"},                                                                        // automatically detects ToTP
	"Shibboleth":    []string{"Auto"},
	"F5APM":         []string{"Auto"},
	"Akamai":        []string{"Auto", "DUO", "SMS", "EMAIL", "TOTP"},
	"ShibbolethECP": []string{"auto", "phone", "push", "passcode"},
	"NetIQ":         []string{"Auto", "Privileged"},
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
	Validate(loginDetails *creds.LoginDetails) error
}

// NewSAMLClient create a new SAML client
func NewSAMLClient(idpAccount *cfg.IDPAccount) (SAMLClient, error) {
	switch idpAccount.Provider {
	case "AzureAD":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return aad.New(idpAccount)
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
	case "PingOne":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return pingone.New(idpAccount)
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
	case "OneLogin":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return onelogin.New(idpAccount)
	case "KeyCloak":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return keycloak.New(idpAccount)
	case "GoogleApps":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return googleapps.New(idpAccount)
	case "Shibboleth":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return shibboleth.New(idpAccount)
	case "ShibbolethECP":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return shibbolethecp.New(idpAccount)
	case "F5APM":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return f5apm.New(idpAccount)
	case "Akamai":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return akamai.New(idpAccount)
	case "Shell":
		return shell.New(idpAccount)
	case "NetIQ":
		if invalidMFA(idpAccount.Provider, idpAccount.MFA) {
			return nil, fmt.Errorf("Invalid MFA type: %v for %v provider", idpAccount.MFA, idpAccount.Provider)
		}
		return netiq.New(idpAccount, idpAccount.MFA)
	default:
		return nil, fmt.Errorf("Invalid provider: %v", idpAccount.Provider)
	}
}
