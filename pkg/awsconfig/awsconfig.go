package awsconfig

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

// AWSConfig represents the set of attributes used to configure AWS profiles
type AWSConfig struct {
	AWSAccessKey     string    `ini:"aws_access_key_id"`
	AWSSecretKey     string    `ini:"aws_secret_access_key"`
	AWSSessionToken  string    `ini:"aws_session_token"`
	AWSSecurityToken string    `ini:"aws_security_token"`
	RoleARN     	 string    `ini:"role_arn"`
	SourceProfile    string    `ini:"source_profile"`
	SessionDuration  string    `ini:"duration_seconds"`
}


// ConfigProvider loads aws config file
type ConfigProvider struct {
	Filename string
	Profile  string
}

// NewSharedConfig helper to create the config provider
func NewSharedConfig(profile string) *ConfigProvider {
	return &ConfigProvider{
		Profile: profile,
	}
}

// CredsExists verify that the credentials exist
func (p *ConfigProvider) ConfigExists() (bool, error) {
	filename, err := p.resolveFilename()
	if err != nil {
		return false, err
	}

	err = p.ensureConfigExists()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrapf(err, "unable to load file %s", filename)
	}

	return true, nil
}

// Save persist the credentials
func (p *ConfigProvider) Save(awsCreds *AWSConfig) error {
	filename, err := p.resolveFilename()
	if err != nil {
		return err
	}

	err = p.ensureConfigExists()
	if err != nil {
		if os.IsNotExist(err) {
			return createAndSaveProfile(filename, p.Profile, awsCreds)
		}
		return errors.Wrap(err, "unable to load file")
	}

	return saveProfile(filename, p.Profile, awsCreds)
}

// Load load the aws credentials file
func (p *ConfigProvider) Load() (*AWSConfig, error) {
	filename, err := p.resolveFilename()
	if err != nil {
		return nil, err
	}

	config, err := ini.Load(filename)
	if err != nil {
		return nil, err
	}

	iniProfile, err := config.GetSection(fmt.Sprintf("profile %s", p.Profile))
	if err != nil {
		return nil, ErrConfigNotFound
	}

	awsCreds := new(AWSConfig)

	err = iniProfile.MapTo(awsCreds)
	if err != nil {
		return nil, ErrConfigNotFound
	}

	return awsCreds, nil
}

// ensureConfigExists verify that the config file exists
func (p *ConfigProvider) ensureConfigExists() error {
	filename, err := p.resolveFilename()
	if err != nil {
		return err
	}
	logger.WithField("filename", filename).Debug("ensureConfigExists")

	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {

			dir := filepath.Dir(filename)

			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return err
			}

			logger.WithField("dir", dir).Debug("Dir created")

			// create an base config file
			err = ioutil.WriteFile(filename, []byte("[profile "+p.Profile+"]"), 0600)
			if err != nil {
				return err
			}

			logger.WithField("filename", filename).Debug("File created")

		}
		return err
	}

	return nil
}

func (p *ConfigProvider) resolveFilename() (string, error) {
	if p.Filename == "" {
		filename, err := locateConfigFile()
		if err != nil {
			return "", err
		}

		p.Filename = filename
	}

	return p.Filename, nil
}

func locateConfigFile() (string, error) {
	filename := os.Getenv("AWS_CONFIG_FILE")

	if filename != "" {
		return filename, nil
	}

	var name string
	var err error
	if runtime.GOOS == "windows" {
		name = path.Join(os.Getenv("USERPROFILE"), ".aws", "config")
	} else {
		name, err = homedir.Expand("~/.aws/config")
		if err != nil {
			return "", ErrHomeNotFound
		}
	}
	logger.WithField("name", name).Debug("Expand")

	// is the filename a symlink?
	name, err = resolveSymlink(name)
	if err != nil {
		return "", errors.Wrap(err, "unable to resolve symlink")
	}

	logger.WithField("name", name).Debug("resolveSymlink")

	return name, nil
}

func createAndSaveProfile(filename, profile string, awsProfile *AWSConfig) error {
	dirPath := filepath.Dir(filename)

	err := os.Mkdir(dirPath, 0700)
	if err != nil {
		return errors.Wrapf(err, "unable to create %s directory", dirPath)
	}

	_, err = os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, "unable to create configuration")
	}

	return saveProfile(filename, profile, awsProfile)
}

func saveProfile(filename, profile string, awsProfile *AWSConfig) error {
	config, err := ini.Load(filename)
	if err != nil {
		return err
	}
	iniProfile, err := config.NewSection(fmt.Sprintf("profile %s", profile))
	if err != nil {
		return err
	}

	err = iniProfile.ReflectFrom(awsProfile)
	if err != nil {
		return err
	}

	return config.SaveTo(filename)
}
