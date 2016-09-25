package saml2aws

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	ini "gopkg.in/ini.v1"
)

var (
	// ErrConfigHomeNotFound returned when a user home directory can't be located.
	ErrConfigHomeNotFound = errors.New("user home directory not found")

	// ErrConfigFileNotFound returned when the required aws credentials file doesn't exist.
	ErrConfigFileNotFound = errors.New("aws credentials file not found")
)

// ConfigLoader loads config options
type ConfigLoader struct {
	Filename string
	Profile  string
}

// NewConfigLoader helper to create the config
func NewConfigLoader(profile string) *ConfigLoader {
	return &ConfigLoader{
		Profile: profile,
	}
}

// ensureConfigExists verify that the config file exists
func (p *ConfigLoader) ensureConfigExists() error {
	filename, err := p.filename()
	if err != nil {
		return err
	}

	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {

			// create an base config file
			err = ioutil.WriteFile(filename, []byte("["+p.Profile+"]"), 0600)
			if err != nil {
				return err
			}

		}
		return err
	}

	return nil
}

// SaveUsername persist the username
func (p *ConfigLoader) SaveUsername(username string) error {
	filename, err := p.filename()
	if err != nil {
		return err
	}

	return saveConfig(filename, p.Profile, "username", username)
}

// LoadUsername load the username
func (p *ConfigLoader) LoadUsername() (string, error) {
	filename, err := p.filename()
	if err != nil {
		return "", err
	}

	err = p.ensureConfigExists()
	if err != nil {
		return "", err
	}

	return loadConfig(filename, p.Profile, "username")
}

// SaveHostname persist the hostname
func (p *ConfigLoader) SaveHostname(hostname string) error {
	filename, err := p.filename()
	if err != nil {
		return err
	}

	return saveConfig(filename, p.Profile, "hostname", hostname)
}

// LoadHostname load the hostname
func (p *ConfigLoader) LoadHostname() (string, error) {
	filename, err := p.filename()
	if err != nil {
		return "", err
	}

	err = p.ensureConfigExists()
	if err != nil {
		return "", err
	}

	return loadConfig(filename, p.Profile, "hostname")
}

// Load the mapping URL
func (p *ConfigLoader) LoadMappingURL() (string, error) {
        filename, err := p.filename()
        if err != nil {
                return "", err
        }

        err = p.ensureConfigExists()
        if err != nil {
                return "", err
        }

        return loadConfig(filename, p.Profile, "mappingurl")
}

// LoadPassword load the password (Not sure how the hell we should handle this)
func (p *ConfigLoader) LoadPassword() (string, error) {
        filename, err := p.filename()
        if err != nil {
                return "", err
        }

        err = p.ensureConfigExists()
        if err != nil {
                return "", err
        }

        return loadConfig(filename, p.Profile, "password")
}

func (p *ConfigLoader) filename() (string, error) {
	if p.Filename == "" {
		if p.Filename = os.Getenv("AWS2SAML_CONFIG_FILE"); p.Filename != "" {
			return p.Filename, nil
		}

		homeDir := os.Getenv("HOME") // *nix
		if homeDir == "" {           // Windows
			homeDir = os.Getenv("USERPROFILE")
		}
		if homeDir == "" {
			return "", ErrConfigHomeNotFound
		}

		p.Filename = filepath.Join(homeDir, ".aws2saml.config")
	}

	return p.Filename, nil
}

func loadConfig(filename, profile, field string) (string, error) {
	config, err := ini.Load(filename)
	if err != nil {
		return "", err
	}
	iniProfile, err := config.GetSection(profile)
	if err != nil {
		return "", err
	}

	return iniProfile.Key(field).String(), nil

}

func saveConfig(filename, profile, field, value string) error {
	config, err := ini.Load(filename)
	if err != nil {
		return err
	}
	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return err
	}

	_, err = iniProfile.NewKey(field, value)
	if err != nil {
		return err
	}

	return config.SaveTo(filename)
}
