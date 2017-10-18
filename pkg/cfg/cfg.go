package cfg

import (
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	ini "gopkg.in/ini.v1"
)

// DefaultConfigPath the default saml2aws configuration path
var DefaultConfigPath = "~/.saml2aws"

// IDPAccount saml IDP account
type IDPAccount struct {
	Hostname   string `ini:"hostname"`
	Username   string `ini:"username"`
	Provider   string `ini:"provider"`
	MFA        string `ini:"mfa"`
	SkipVerify bool   `ini:"skip_verify"`
	Timeout    int    `ini:"timeout"`
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

// SaveIDPAccount save idp account
func (cm *ConfigManager) SaveIDPAccount(idpAccountName string, account *IDPAccount) error {

	cfg, err := ini.LoadSources(ini.LoadOptions{Loose: true}, cm.configPath)
	if err != nil {
		return errors.Wrap(err, "Unable to load configuration file")
	}

	newSec, err := cfg.NewSection(idpAccountName)
	if err != nil {
		return errors.Wrap(err, "Unable to build a new section in configuration file")
	}

	err = newSec.ReflectFrom(account)
	if err != nil {
		return errors.Wrap(err, "Unable to save account to configuration file")
	}

	err = cfg.SaveTo(cm.configPath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration file")
	}
	return nil
}

// LoadIDPAccount load the idp account and default to an empty one if it doesn't exist
func (cm *ConfigManager) LoadIDPAccount(idpAccountName string) (*IDPAccount, error) {

	account := new(IDPAccount)

	cfg, err := ini.LoadSources(ini.LoadOptions{Loose: true}, cm.configPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to load configuration file")
	}

	sec := cfg.Section(idpAccountName)

	err = sec.MapTo(account)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to load configuration file")
	}

	return account, nil
}
