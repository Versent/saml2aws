package samlcache

import (
	b64 "encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	saml2aws "github.com/versent/saml2aws/v2"
)

var (
	ErrInvalidCachePath = errors.New("Cannot evaluate Cache file path")
	logger              = logrus.WithField("pkg", "samlcache")
)

const (
	// SAMLAssertionValidityJitter is a small time delta used to avoid the race condition
	// where a token expires between the time it's validated and re-used.
	SAMLAssertionValidityJitter = -1 * time.Second
	SAMLCacheFilePermissions    = 0600
	SAMLCacheDirPermissions     = 0700
	SAMLCacheDir                = "saml2aws"
)

// SAMLCacheProvider  loads aws credentials file
type SAMLCacheProvider struct {
	Filename string
	Account  string
}

func resolveSymlink(filename string) (string, error) {
	sympath, err := filepath.EvalSymlinks(filename)

	// return the un modified filename
	if os.IsNotExist(err) {
		return filename, nil
	}
	if err != nil {
		return "", err
	}

	return sympath, nil
}

func (p *SAMLCacheProvider) IsValid() bool {
	var cache_path string
	var err error

	logger := logger.WithField("IdpAccount", p.Account)
	if p.Filename == "" {
		cache_path, err = locateCacheFile(p.Account)
		if err != nil {
			logger.Debug("Could not retrieve cache file location", err)
			return false
		}
	} else {
		cache_path = p.Filename
	}
	logger = logger.WithField("Cache_file", cache_path)

	raw, err := os.ReadFile(cache_path)
	if err != nil {
		logger.Debug("Could not read cache content", err)
		return false
	}

	data, err := b64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		logger.Debug("Could not decode cache content", err)
		return false
	}

	ValidUntil, err := saml2aws.ExtractMFATokenExpiryTime(data)
	if err != nil {
		logger.Debug("Could not extract a valid expiry time for the MFA token", err)
		return false
	}

	logger.Debug("MFA Token expiry date:", ValidUntil.Format(time.RFC3339))

	return time.Now().Before(ValidUntil.Add(SAMLAssertionValidityJitter))
}

func locateCacheFile(account string) (string, error) {

	var name, filename string
	var err error
	if account == "" {
		filename = "cache"
	} else {
		filename = fmt.Sprintf("cache_%s", account)
	}
	if runtime.GOOS == "windows" {
		name = path.Join(os.Getenv("USERPROFILE"), ".aws", SAMLCacheDir, filename)
	} else {
		name, err = homedir.Expand(path.Join("~", ".aws", SAMLCacheDir, filename))
		if err != nil {
			return "", ErrInvalidCachePath
		}
	}
	// is the filename a symlink?
	name, err = resolveSymlink(name)
	if err != nil {
		return "", errors.Wrap(err, "unable to resolve symlink")
	}

	logger.WithField("name", name).Debug("resolveSymlink")

	return name, nil
}

func (p *SAMLCacheProvider) ReadRaw() (string, error) {

	var cache_path string
	var err error
	if p.Filename == "" {
		cache_path, err = locateCacheFile(p.Account)
		if err != nil {
			return "", errors.Wrap(err, "Could not retrieve cache file path")
		}
	} else {
		cache_path = p.Filename
	}

	content, err := os.ReadFile(cache_path)
	if err != nil {
		return "", errors.Wrap(err, "Could not read the cache file path")
	}

	return string(content), nil
}

func (p *SAMLCacheProvider) WriteRaw(samlAssertion string) error {

	var cache_path string
	var err error
	if p.Filename == "" {
		cache_path, err = locateCacheFile(p.Account)
		if err != nil {
			return errors.Wrap(err, "Could not retrieve cache file path")
		}
	} else {
		cache_path = p.Filename
	}

	// create the directory if it doesn't exist
	err = os.MkdirAll(path.Dir(cache_path), SAMLCacheDirPermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file directory")
	}
	err = os.WriteFile(cache_path, []byte(samlAssertion), SAMLCacheFilePermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file path")
	}

	return nil
}
