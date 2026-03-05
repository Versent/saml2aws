package awsconfig

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	ini "gopkg.in/ini.v1"
)

func TestUpdateSamlConfig(t *testing.T) {
	os.Remove(".credentials")

	logrus.SetLevel(logrus.DebugLevel)

	sharedCreds := &CredentialsProvider{".credentials", "saml"}

	exist, err := sharedCreds.CredsExists()
	assert.Nil(t, err)
	assert.True(t, exist)

	awsCreds := &AWSCredentials{
		AWSAccessKey:     "testid",
		AWSSecretKey:     "testsecret",
		AWSSessionToken:  "testtoken",
		AWSSecurityToken: "testtoken",
	}

	err = sharedCreds.Save(awsCreds)
	assert.Nil(t, err)

	awsCreds, err = sharedCreds.Load()
	assert.Nil(t, err)
	assert.Equal(t, "testid", awsCreds.AWSAccessKey)
	assert.Equal(t, "testsecret", awsCreds.AWSSecretKey)
	assert.Equal(t, "testtoken", awsCreds.AWSSessionToken)

	os.Remove(".credentials")
	os.Remove(lockFilePath(".credentials"))
}

func TestConcurrentSave(t *testing.T) {
	const filename = ".credentials_concurrent"
	const numWorkers = 10

	os.Remove(filename)
	os.Remove(lockFilePath(filename))
	defer os.Remove(filename)
	defer os.Remove(lockFilePath(filename))

	// Create the initial file so ensureConfigExists doesn't race
	err := os.WriteFile(filename, []byte("[default]"), 0600)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			profile := fmt.Sprintf("profile-%d", idx)
			creds := &CredentialsProvider{Filename: filename, Profile: profile}
			awsCreds := &AWSCredentials{
				AWSAccessKey:     fmt.Sprintf("key-%d", idx),
				AWSSecretKey:     fmt.Sprintf("secret-%d", idx),
				AWSSessionToken:  fmt.Sprintf("token-%d", idx),
				AWSSecurityToken: fmt.Sprintf("sectoken-%d", idx),
			}
			if err := creds.Save(awsCreds); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent save error: %v", err)
	}

	// Verify no duplicate sections
	config, err := ini.Load(filename)
	assert.NoError(t, err)

	sectionNames := config.SectionStrings()
	seen := make(map[string]bool)
	for _, name := range sectionNames {
		if seen[name] {
			t.Errorf("duplicate section found: %s", name)
		}
		seen[name] = true
	}

	// Verify all profiles are present
	for i := 0; i < numWorkers; i++ {
		profile := fmt.Sprintf("profile-%d", i)
		assert.True(t, seen[profile], "missing profile: %s", profile)
	}

	// Verify file content has no duplicate section headers via raw text
	data, err := os.ReadFile(filename)
	assert.NoError(t, err)
	content := string(data)
	for i := 0; i < numWorkers; i++ {
		header := fmt.Sprintf("[profile-%d]", i)
		count := strings.Count(content, header)
		assert.Equal(t, 1, count, "expected exactly 1 occurrence of %s, got %d", header, count)
	}
}
