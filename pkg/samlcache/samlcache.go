package samlcache

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ErrInvalidCachePath = errors.New("Cannot evaluate Cache file path")
	logger              = logrus.WithField("pkg", "samlcache")
)

const (
	SAMLAssertionValidityTimeout = 5 * time.Minute
	SAMLCacheFilePermissions     = 0600
	SAMLCacheDirPermissions      = 0700
	SAMLCacheDir                 = "saml2aws"
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
	if p.Filename == "" {
		cache_path, err = locateCacheFile(p.Account)
		if err != nil {
			return false
		}
	} else {
		cache_path = p.Filename
	}

	fileInfo, err := os.Stat(cache_path)
	if err != nil {
		return false
	}

	return time.Since(fileInfo.ModTime()) < SAMLAssertionValidityTimeout
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

func (p *SAMLCacheProvider) Read() (string, error) {

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

	content, err := ioutil.ReadFile(cache_path)
	if err != nil {
		return "", errors.Wrap(err, "Could not read the cache file path")
	}

	return string(content), nil
}

func (p *SAMLCacheProvider) Write(samlAssertion string) error {

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
	err = ioutil.WriteFile(cache_path, []byte(samlAssertion), SAMLCacheFilePermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file path")
	}

	return nil
}
