package samlcache

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
)

func TestLocateCacheDefault(t *testing.T) {

	cache_location, err := locateCacheFile("")
	if err != nil {
		t.Error("Could not locate cache file:", err)
	}

	if cache_location == "" {
		t.Error("Retrieved location is empty")
	}

	if path.Base(cache_location) != "cache" {
		t.Error("Filename is not the default one (cache):", path.Base(cache_location))
	}

}

func TestLocateCacheAccount(t *testing.T) {

	cache_location, err := locateCacheFile("myaccount")
	if err != nil {
		t.Error("Could not locate cache file:", err)
	}

	if cache_location == "" {
		t.Error("Retrieved location is empty")
	}

	if path.Base(cache_location) != "cache_myaccount" {
		t.Error("Filename is not the default one (cache_myaccount):", path.Base(cache_location))
	}

}

func TestCanWrite(t *testing.T) {

	p := SAMLCacheProvider{
		Filename: "testdir/cache_file",
	}

	err := p.Write("test_write_cache")
	if err != nil {
		t.Error("Could not write cache:", err)
	}

	if _, err := os.Stat("testdir/cache_file"); os.IsNotExist(err) {
		t.Error("The cache file was not created:", err)
	}

	os.RemoveAll("testdir")

}

func TestCanRead(t *testing.T) {

	// create a dummy file
	_ = ioutil.WriteFile("example_cache", []byte("testing output"), 0700)

	p := SAMLCacheProvider{
		Filename: "example_cache",
	}

	output, err := p.Read()
	if err != nil {
		t.Error("Could not read cache:", err)
	}

	if output != "testing output" {
		t.Error("Cache file does not contain the right thing", output)
	}

	os.Remove("example_cache")

}

func TestIsValid(t *testing.T) {

	// create a dummy file
	_ = ioutil.WriteFile("example_cache", []byte("testing output"), 0700)
	p := SAMLCacheProvider{
		Filename: "example_cache",
	}

	if !p.IsValid() {
		t.Error("Cache file is not valid!")
	}

	// changing the file timestamp to validate expiry
	// new_time := time.Now().Sub(24 * time.Hour)
	new_time := time.Now().Add(-24 * time.Hour)
	_ = os.Chtimes("example_cache", new_time, new_time)

	if p.IsValid() {
		t.Error("Cache file should be expired!")
	}

	os.Remove("example_cache")

}
