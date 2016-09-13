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

// Config loads config options
type Config struct {
	Filename string
	Profile  string
}

// NewConfig helper to create the config
func NewConfig(profile string) *Config {
	return &Config{
		Profile: profile,
	}
}

// Exists verify that the credentials file exists
func (p *Config) exists() (bool, error) {
	filename, err := p.filename()
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// SaveUsername persist the username
func (p *Config) SaveUsername(username string) error {
	filename, err := p.filename()
	if err != nil {
		return err
	}

	return saveConfig(filename, p.Profile, username)
}

// LoadUsername persist the username
func (p *Config) LoadUsername() (string, error) {
	filename, err := p.filename()
	if err != nil {
		return "", err
	}

	exists, err := p.exists()
	if err != nil {
		return "", err
	}

	if !exists {
		// create an base config file
		err = ioutil.WriteFile(filename, []byte("["+p.Profile+"]"), 0666)
	}
	if err != nil {
		return "", err
	}

	return loadConfig(filename, p.Profile)
}

func (p *Config) filename() (string, error) {
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

func loadConfig(filename, profile string) (string, error) {
	config, err := ini.Load(filename)
	if err != nil {
		return "", err
	}
	iniProfile, err := config.GetSection(profile)
	if err != nil {
		return "", err
	}

	return iniProfile.Key("username").String(), nil

}

func saveConfig(filename, profile, username string) error {
	config, err := ini.Load(filename)
	if err != nil {
		return err
	}
	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return err
	}

	_, err = iniProfile.NewKey("username", username)
	if err != nil {
		return err
	}

	return config.SaveTo(filename)
}
