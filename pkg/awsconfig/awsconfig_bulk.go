package awsconfig

import (
	"os"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/ini.v1"
)

// CredentialsFile holds the original ini file to eliminate reading it multiple times throughout the process
type CredentialsFile struct {
	File *ini.File

	fileLoc string
}

// LoadCredentialsFile loads the AWS credentials file and keeps it in a config object
// with an optional fileName parameter override
func LoadCredentialsFile(fileName ...string) (*CredentialsFile, error) {
	var file string
	if len(fileName) > 0 {
		// Filename was passed in as an arg
		expanded, err := homedir.Expand(fileName[0])
		if err != nil {
			return nil, err
		}
		file = expanded
	} else {
		// otherwise use default
		f, err := locateConfigFile()
		if err != nil {
			return nil, err
		}
		file = f
	}

	logger.WithField("filename", file).Debug("ensureCredentialsExists")

	if err := ensureCredentialsExist(file); err != nil {
		return nil, err
	}

	// File exists, read it and load it into an ini config
	credsFile, err := ini.Load(file)
	if err != nil {
		return nil, err
	}

	return &CredentialsFile{
		File:    credsFile,
		fileLoc: file,
	}, nil
}

// SaveFile saves the credentials file to where it was loaded from
func (creds *CredentialsFile) SaveFile() error {
	logger.WithField("filename", creds.fileLoc).Debug("storing file")
	return creds.File.SaveTo(creds.fileLoc)
}

// Expired checks to see if a profile is expired or not
func (creds *CredentialsFile) Expired(profile string) bool {
	cred, err := creds.Load(profile)
	if err != nil {
		return true
	}

	return time.Now().After(cred.Expires)
}

// Load loads a credentials file from the
func (creds *CredentialsFile) Load(profile string) (*AWSCredentials, error) {
	iniProfile, err := creds.File.GetSection(profile)
	if err != nil {
		return nil, ErrCredentialsNotFound
	}

	awsCreds := new(AWSCredentials)

	if err := iniProfile.MapTo(awsCreds); err != nil {
		return nil, ErrCredentialsNotFound
	}

	return awsCreds, nil
}

// StoreCreds takes a profile and the awsCreds to store. This does NOT save the file, that needs to be called later
func (creds *CredentialsFile) StoreCreds(profile string, awsCreds *AWSCredentials) error {
	iniProfile, err := creds.File.NewSection(profile)
	if err != nil {
		return err
	}

	if err := iniProfile.ReflectFrom(awsCreds); err != nil {
		return err
	}

	return nil
}

func ensureCredentialsExist(file string) error {
	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			// File does not exist, create it
			dir := filepath.Dir(file)

			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return err
			}

			logger.WithField("dir", dir).Debugf("Dir created")

			if _, err := os.Create(file); err != nil {
				return err
			}

			logger.WithField("file", file).Debugf("File created")
		}
		return nil
	}
	return nil
}
