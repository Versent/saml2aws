package awsconfig

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"

	"github.com/pkg/errors"

	ini "gopkg.in/ini.v1"
)

var (
	// ErrCredentialsHomeNotFound returned when a user home directory can't be located.
	ErrCredentialsHomeNotFound = errors.New("user home directory not found")

	// ErrCredentialsNotFound returned when the required aws credentials don't exist.
	ErrCredentialsNotFound = errors.New("aws credentials not found")
)

// AWSCredentials represents the set of attributes used to authenticate to AWS with a short lived session
type AWSCredentials struct {
	AWSAccessKey     string `ini:"aws_access_key_id"`
	AWSSecretKey     string `ini:"aws_secret_access_key"`
	AWSSessionToken  string `ini:"aws_session_token"`
	AWSSecurityToken string `ini:"aws_security_token"`
}

// CredentialsProvider loads aws credentials file
type CredentialsProvider struct {
	Filename string
	Profile  string
}

// NewSharedCredentials helper to create the credentials provider
func NewSharedCredentials(profile string) *CredentialsProvider {
	return &CredentialsProvider{
		Profile: profile,
	}
}

// CredsExists verify that the credentials exist
func (p *CredentialsProvider) CredsExists() (bool, error) {
	filename, err := p.filename()
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
func (p *CredentialsProvider) Save(id, secret, token string) error {
	filename, err := p.filename()
	if err != nil {
		return err
	}

	err = p.ensureConfigExists()
	if err != nil {
		if os.IsNotExist(err) {
			return createAndSaveProfile(filename, p.Profile, id, secret, token)
		}
		return errors.Wrap(err, "unable to load file")
	}

	return saveProfile(filename, p.Profile, id, secret, token)
}

// Load load the aws credentials file
func (p *CredentialsProvider) Load() (string, string, string, error) {
	filename, err := p.filename()
	if err != nil {
		return "", "", "", err
	}

	config, err := ini.Load(filename)
	if err != nil {
		return "", "", "", err
	}

	iniProfile, err := config.GetSection(p.Profile)
	if err != nil {
		return "", "", "", ErrCredentialsNotFound
	}

	awsCreds := new(AWSCredentials)

	err = iniProfile.MapTo(awsCreds)
	if err != nil {
		return "", "", "", ErrCredentialsNotFound
	}

	return awsCreds.AWSAccessKey, awsCreds.AWSSecretKey, awsCreds.AWSSecurityToken, nil
}

// ensureConfigExists verify that the config file exists
func (p *CredentialsProvider) ensureConfigExists() error {
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

func (p *CredentialsProvider) filename() (string, error) {
	if p.Filename == "" {
		if p.Filename = os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p.Filename != "" {
			return p.Filename, nil
		}

		name, err := homedir.Expand("~/.aws/credentials")
		if err != nil {
			return "", ErrCredentialsHomeNotFound
		}

		// is the filename a symlink?
		name, err = filepath.EvalSymlinks(name)
		if err != nil {
			return "", errors.Wrap(err, "unable to resolve symlink")
		}

		p.Filename = name
	}

	return p.Filename, nil
}

func createAndSaveProfile(filename, profile, id, secret, token string) error {

	dirPath := filepath.Dir(filename)

	err := os.Mkdir(dirPath, 0700)
	if err != nil {
		return errors.Wrapf(err, "unable to create %s directory", dirPath)
	}

	_, err = os.Create(filename)
	if err != nil {
		return errors.Wrapf(err, "unable to create configuration")
	}

	return saveProfile(filename, profile, id, secret, token)
}

func saveProfile(filename, profile, id, secret, token string) error {
	config, err := ini.Load(filename)
	if err != nil {
		return err
	}
	iniProfile, err := config.NewSection(profile)
	if err != nil {
		return err
	}

	err = iniProfile.ReflectFrom(&AWSCredentials{
		AWSAccessKey:     id,
		AWSSecretKey:     secret,
		AWSSessionToken:  token,
		AWSSecurityToken: token,
	})
	if err != nil {
		return err
	}

	return config.SaveTo(filename)
}
