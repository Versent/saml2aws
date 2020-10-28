package cfg

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"runtime"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

var Version string

// ErrIdpAccountNotFound returned if the idp account is not found in the configuration file
var ErrIdpAccountNotFound = errors.New("IDP account not found, run configure to set it up")

const (
	// DefaultConfigPath the default gossamer3 configuration path
	DefaultConfigPath = "~/.gossamer3.yaml"

	// DefaultAmazonWebservicesURN URN used when authenticating to aws using SAML
	// NOTE: This only needs to be changed to log into GovCloud
	DefaultAmazonWebservicesURN = "urn:amazon:webservices"

	// DefaultSessionDuration this is the default session duration which can be overridden in the AWS console
	// see https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/
	DefaultSessionDuration = 3600

	// DefaultProfile this is the default profile name used to save the credentials in the aws cli
	DefaultProfile = "saml"

	// DefaultName defaults to default for UX yo
	DefaultName = "default"

	// DefaultTimeout defaults to 10 seconds, overwritten by what is in the .gossamer3.yaml file
	DefaultTimeout = 10
)

// IDPAccount saml IDP account
type IDPAccount struct {
	Name                 string `yaml:"name"`
	URL                  string `yaml:"url"`
	Username             string `yaml:"username"`
	Provider             string `yaml:"provider"`
	MFA                  string `yaml:"mfa"`
	MFADevice            string `yaml:"mfa_device"`
	MFAPrompt            bool   `yaml:"mfa_prompt"`
	SkipVerify           bool   `yaml:"skip_verify"`
	Timeout              int    `yaml:"timeout"`
	AmazonWebservicesURN string `yaml:"aws_urn"`
	SessionDuration      int    `yaml:"aws_session_duration"`
	Profile              string `yaml:"aws_profile"`
	RoleARN              string `yaml:"role_arn"`
	Region               string `yaml:"region"`
	HttpAttemptsCount    string `yaml:"http_attempts_count"`
	HttpRetryDelay       string `yaml:"http_retry_delay"`
}

func GetUserAgent() string {
	return fmt.Sprintf("gossamer3/%s (%s; %s; %s)", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func (ia IDPAccount) String() string {
	return fmt.Sprintf(`account {
  Name: %s
  URL: %s
  Username: %s
  Provider: %s
  MFA: %s
  SkipVerify: %v
  AmazonWebservicesURN: %s
  SessionDuration: %d
  Profile: %s
  RoleARN: %s
  Region: %s
}`, ia.Name, ia.URL, ia.Username, ia.Provider, ia.MFA, ia.SkipVerify, ia.AmazonWebservicesURN, ia.SessionDuration, ia.Profile, ia.RoleARN, ia.Region)
}

// Validate validate the required / expected fields are set
func (ia *IDPAccount) Validate() error {
	if ia.URL == "" {
		return errors.New("URL empty in idp account")
	}

	_, err := url.Parse(ia.URL)
	if err != nil {
		return errors.New("URL parse failed")
	}

	if ia.Provider == "" {
		return errors.New("Provider empty in idp account")
	}

	if ia.MFA == "" {
		return errors.New("MFA empty in idp account")
	}

	if ia.Profile == "" {
		return errors.New("Profile empty in idp account")
	}

	return nil
}

// NewIDPAccount Create an idp account and fill in any default fields with sane values
func NewIDPAccount() *IDPAccount {
	account := setDefaults(IDPAccount{})
	return &account
}

// ConfigManager manage the various IDP account settings
type ConfigManager struct {
	configPath string
}

// NewConfigManager build a new config manager and optionally override the config path
func NewConfigManager(configFile string) (*ConfigManager, error) {

	if configFile == "" {
		configFile = DefaultConfigPath
	}

	configPath, err := homedir.Expand(configFile)
	if err != nil {
		return nil, err
	}

	return &ConfigManager{configPath}, nil
}

func setDefaults(account IDPAccount) IDPAccount {
	if account.Name == "" {
		account.Name = DefaultName
	}
	if account.Profile == "" {
		account.Profile = DefaultProfile
	}
	if account.AmazonWebservicesURN == "" {
		account.AmazonWebservicesURN = DefaultAmazonWebservicesURN
	}
	if account.SessionDuration == 0 {
		account.SessionDuration = DefaultSessionDuration
	}
	if account.Timeout == 0 {
		account.Timeout = DefaultTimeout
	}

	return account
}

// SaveIDPAccount save idp account
func (cm *ConfigManager) SaveIDPAccount(account *IDPAccount) error {

	if err := account.Validate(); err != nil {
		return errors.Wrap(err, "Account validation failed")
	}

	providers, err := cm.loadIDPAccounts()
	if err != nil {
		return errors.Wrap(err, "Unable to read providers config")
	}

	// Add new IDP to Providers
	providers = overwriteAccount(*account, providers)

	bs, err := yaml.Marshal(providers)
	if err != nil {
		return errors.Wrap(err, "Unable to marshal providers json")
	}

	// Write the file
	if err := ioutil.WriteFile(cm.configPath, bs, 0666); err != nil {
		return errors.Wrap(err, "Failed to save configurations file")
	}

	return nil
}

// LoadIDPAccount load the idp account and default to an empty one if it doesn't exist
func (cm *ConfigManager) LoadIDPAccount(idpAccountName string) (*IDPAccount, error) {
	providers, err := cm.loadIDPAccounts()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read idp account")
	}

	// attempt to map a specific idp account by name
	// this will return an empty account if one is not found by the given name
	account, err := readAccount(idpAccountName, providers)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to read idp account")
	}

	return account, nil
}

func (cm *ConfigManager) loadIDPAccounts() ([]IDPAccount, error) {
	_, err := os.Stat(cm.configPath)
	if os.IsNotExist(err) {
		// File does not exist
		return []IDPAccount{}, nil
	}

	bs, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to load configurations file")
	}

	var providers []IDPAccount
	if err := yaml.Unmarshal(bs, &providers); err != nil {
		return nil, errors.Wrap(err, "Unable to read idp accounts from config")
	}

	// Set default values if they are not provided
	for i, provider := range providers {
		providers[i] = setDefaults(provider)
	}

	return providers, nil
}

func readAccount(idpAccountName string, providers []IDPAccount) (*IDPAccount, error) {
	for _, provider := range providers {
		if provider.Name == idpAccountName {
			return &provider, nil
		}
	}

	return nil, nil
}

func overwriteAccount(newAccount IDPAccount, providers []IDPAccount) []IDPAccount {
	var found = false
	for i, provider := range providers {
		if provider.Name == newAccount.Name {
			providers[i] = newAccount
			found = true
			break
		}
	}

	if !found {
		providers = append(providers, setDefaults(newAccount))
	}

	return providers
}
