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
	SAMLCacheDir                 = ".saml2aws_cache"
)

// SAMLCacheProvider  loads aws credentials file
type SAMLCacheProvider struct {
	Filename string
	Profile  string
}

func NewSAMLCacheProvider(profile string, filename string) *SAMLCacheProvider {
	p := &SAMLCacheProvider{
		Filename: filename,
		Profile:  profile,
	}
	return p
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

func (p *SAMLCacheProvider) IsValid() (bool, error) {
	var cache_path string
	var err error
	if p.Filename == "" {
		cache_path, err = locateCacheFile(p.Profile)
		if err != nil {
			logger.Debug("Could not retrieve cache file path")
			return false, err
		}
	} else {
		cache_path = p.Filename
	}

	fileInfo, err := os.Stat(cache_path)
	if err != nil {
		return false, errors.Wrap(err, "Could not access cache file info")
	}

	// 	if !(fileInfo.Mode()&0700 == 0700) {
	// 		return false, errors.New("Cache does not have read and write access")
	// 	}

	if time.Since(fileInfo.ModTime()) < SAMLAssertionValidityTimeout {
		return true, nil
	} else {
		return false, errors.New("Cache is expired")
	}
}

func locateCacheFile(profile string) (string, error) {

	var name, filename string
	var err error
	if profile == "" {
		filename = "cache"
	} else {
		filename = fmt.Sprintf("cache_%s", profile)
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
		cache_path, err = locateCacheFile(p.Profile)
		if err != nil {
			logger.Debug("Could not retrieve cache file path")
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
		cache_path, err = locateCacheFile(p.Profile)
		if err != nil {
			logger.Debug("Could not retrieve cache file path")
			return errors.Wrap(err, "Could not retrieve cache file path")
		}
	} else {
		cache_path = p.Filename
	}

	// create the directory if it doesn't exist
	logger.Debug("Going to MkDir:", path.Dir(p.Filename))
	err = os.MkdirAll(path.Dir(cache_path), SAMLCacheDirPermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file directory")
	}
	logger.Debug("Writing file", cache_path)
	err = ioutil.WriteFile(cache_path, []byte(samlAssertion), SAMLCacheFilePermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file path")
	}

	return nil
}
