package samlcache

import (
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
	SAMLCachePermissions         = 0600
	SAMLCacheFilename            = ".saml2aws_cache"
)

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

func locateCacheFile() (string, error) {

	var name string
	var err error
	if runtime.GOOS == "windows" {
		name = path.Join(os.Getenv("USERPROFILE"), ".aws", SAMLCacheFilename)
	} else {
		name, err = homedir.Expand(path.Join("~", ".aws", SAMLCacheFilename))
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

func IsValidCache() bool {

	cache_path, err := locateCacheFile()
	if err != nil {
		logger.Debug("Could not retrieve cache file path")
		return false
	}

	fileInfo, err := os.Stat(cache_path)
	if err != nil {
		logger.Error("Could not access cache file info")
		return false
	}

	return time.Since(fileInfo.ModTime()) < SAMLAssertionValidityTimeout
}

func ReadCache() (string, error) {

	cache_path, err := locateCacheFile()
	if err != nil {
		return "", errors.Wrap(err, "Could not retrieve cache file path")
	}

	content, err := ioutil.ReadFile(cache_path)
	if err != nil {
		return "", errors.Wrap(err, "Could not read the cache file path")
	}

	return string(content), nil
}

func WriteCache(samlAssertion string) error {

	cache_path, err := locateCacheFile()
	if err != nil {
		return errors.Wrap(err, "Could not retrieve cache file path")
	}

	err = ioutil.WriteFile(cache_path, []byte(samlAssertion), SAMLCachePermissions)
	if err != nil {
		return errors.Wrap(err, "Could not write the cache file path")
	}

	return nil
}
