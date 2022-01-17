package samlcache

import (
	b64 "encoding/base64"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"text/template"
	"time"
)

const (
	AssertionCacheValidityTemplateFileName = "testdata/assertion_validity_template.gotmpl"
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

	err := p.WriteRaw("test_write_cache")
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

	output, err := p.ReadRaw()
	if err != nil {
		t.Error("Could not read cache:", err)
	}

	if output != "testing output" {
		t.Error("Cache file does not contain the right thing", output)
	}

	os.Remove("example_cache")

}

type AssertionTemplateData struct {
	ExpiryRFC3339Time string
}

func templateAssertion(t time.Time) (string, error) {

	newfile, _ := os.CreateTemp("", "assert_tmpl_")

	data := AssertionTemplateData{
		ExpiryRFC3339Time: t.Format(time.RFC3339),
	}

	content, _ := ioutil.ReadFile("./assertion_validity_template.gotmpl")
	tmpl, err := template.New("assertion_validity_template").Parse(string(content))
	if err != nil {
		defer os.Remove(newfile.Name())
		return "", err
	}

	encodeWriter := b64.NewEncoder(b64.StdEncoding, newfile)
	err = tmpl.Execute(encodeWriter, data)
	if err != nil {
		defer os.Remove(newfile.Name())
		return "", err
	}

	encodeWriter.Close()
	return newfile.Name(), nil
}

func TestIsValid(t *testing.T) {

	expiresIn10Minutes := time.Now().Add(10 * time.Minute)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	t.Log(tmpFile)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if !p.IsValid() {
		t.Error("Cache file is not valid!")
	}

}

func TestIsValid2(t *testing.T) {

	// a date _really_ close to the expiration should still work
	expiresIn10Minutes := time.Now().Add(2 * time.Second)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	t.Log(tmpFile)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if !p.IsValid() {
		t.Error("Cache file is not valid!")
	}

}

func TestIsNotValid1(t *testing.T) {

	expiresIn10Minutes := time.Now().Add(-10 * time.Minute)
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if p.IsValid() {
		t.Error("The cache has expired 10 minutes ago and should be invalid!")
	}

}

func TestIsNotValid2(t *testing.T) {

	// verifies that the cache is expired if the data is too close to now.
	expiresIn10Minutes := time.Now()
	tmpFile, err := templateAssertion(expiresIn10Minutes)
	defer os.Remove(tmpFile)
	if err != nil {
		t.Error(err)
	}

	p := SAMLCacheProvider{
		Filename: tmpFile,
	}

	if p.IsValid() {
		t.Error("Should be invalid; will expire imminently")
	}

}

func TestIsNotValid3(t *testing.T) {

	// if the cache file doesn't exist, it should be invalid
	p := SAMLCacheProvider{
		Filename: "This_file_does_not_exist",
	}

	if p.IsValid() {
		t.Error("There is no valid cache")
	}

}
