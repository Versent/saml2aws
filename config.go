package saml2aws

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
   "encoding/hex"
    "bytes"
    "golang.org/x/crypto/openpgp"
    "github.com/jcmdev0/gpgagent"
   "encoding/base64"
    "strings"

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

// SavePassword persist the password
func (p *ConfigLoader) SavePassword(password string, email string) error {
        filename, err := p.filename()
        if err != nil {
                return err
        }
        encryptedpassword, _ := encryptPassword(password, email)
        return saveConfig(filename, p.Profile, "password", encryptedpassword)
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
        email, _ := loadConfig(filename, p.Profile, "username")
        encryptedpassword, _ := loadConfig(filename, p.Profile, "password")
        return decryptPassword(encryptedpassword,email)
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
func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
  for _, entity := range keyring {
    for _, ident := range entity.Identities {
      if ident.UserId.Email == email {
        return entity
      }
    }
  }

  return nil
}

func encryptPassword(password string, email string) (string, error) {
    homeDir := os.Getenv("HOME") // *nix
    secretKeyring := homeDir + "/.gnupg/secring.gpg"
    publicKeyring := homeDir + "/.gnupg/pubring.gpg"

    // Read in public key
    keyringFileBuffer, _ := os.Open(publicKeyring)
    defer keyringFileBuffer.Close()
    privringFile, _ := os.Open(secretKeyring)
    privring, _ := openpgp.ReadKeyRing(privringFile)
    // encrypt string
    buf := new(bytes.Buffer)
    myPrivateKey := getKeyByEmail(privring, email)
    w, err := openpgp.Encrypt(buf, []*openpgp.Entity{myPrivateKey}, nil, nil, nil)
    if err != nil {
        return "", err
    }
    _, err = w.Write([]byte(password))
    if err != nil {
        return "", err
    }
    err = w.Close()
    if err != nil {
        return "", err
    }

    // Encode to base64
    bytes, err := ioutil.ReadAll(buf)
    if err != nil {
        return "", err
    }
    encStr := base64.StdEncoding.EncodeToString(bytes)

    return encStr, nil
}

func decryptPassword(encString string, email string) (string, error) {
    homeDir := os.Getenv("HOME") // *nix
    secretKeyring := homeDir + "/.gnupg/secring.gpg"
    conn, err := gpgagent.NewGpgAgentConn()
    if err != nil {
       panic(err)
    }
    defer conn.Close()

    privringFile, _ := os.Open(secretKeyring)
    if err != nil {
	panic(err)
    }
    defer privringFile.Close()
    privring, err := openpgp.ReadKeyRing(privringFile)
    if err != nil {
	panic(err)
    } 
    myPrivateKey := getKeyByEmail(privring, email)
    keyId   := []byte(myPrivateKey.PrivateKey.KeyIdString())
    cacheId := strings.ToUpper(hex.EncodeToString(keyId))
    request := gpgagent.PassphraseRequest{CacheKey: cacheId}
    passphrase, err := conn.GetPassphrase(&request)

    // init some vars
    var entity *openpgp.Entity
    var entityList openpgp.EntityList

    // Open the private key file
    keyringFileBuffer, err := os.Open(secretKeyring)
    if err != nil {
        return "", err
    }
    defer keyringFileBuffer.Close()
    entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
    if err != nil {
        return "", err
    }
    entity = entityList[0]

    passphraseByte := []byte(passphrase)
    entity.PrivateKey.Decrypt(passphraseByte)
    for _, subkey := range entity.Subkeys {
        subkey.PrivateKey.Decrypt(passphraseByte)
    }

    dec, err := base64.StdEncoding.DecodeString(encString)
    if err != nil {
        return "", err
    }

    md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
    if err != nil {
        return "", err
    }
    bytes, err := ioutil.ReadAll(md.UnverifiedBody)
    if err != nil {
        return "", err
    }
    decStr := string(bytes)

    return decStr, nil
}
