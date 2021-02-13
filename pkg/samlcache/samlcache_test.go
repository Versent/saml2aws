package samlcache

import (
	"os"
	"testing"
)

func TestLocateCache(t *testing.T) {

	cache_location, err := locateCacheFile()
	if err != nil {
		t.Errorf("Could not locate cache file: %v", err)
	}

	if cache_location == "" {
		t.Errorf("Retrieved location is empty")
	}

}

func TestCanWriteAndRead(t *testing.T) {

	cache_location, _ := locateCacheFile()

	err := WriteCache("test_write_cache")
	if err != nil {
		t.Errorf("Could not write cache: %v", err)
	}

	content, err := ReadCache()
	if err != nil {
		t.Errorf("Could not read cache: %v", err)
	}
	if content != "test_write_cache" {
		t.Errorf("Content is not as expected: %v", content)
	}

	os.Remove(cache_location)

}
