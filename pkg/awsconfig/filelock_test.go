//go:build !windows
// +build !windows

package awsconfig

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileLockExclusivity(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "locktest")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	lock1, err := newFileLock(tmpFile.Name())
	assert.NoError(t, err)

	err = lock1.Lock()
	assert.NoError(t, err)

	// Try to acquire a second lock in a goroutine — it should block
	var mu sync.Mutex
	acquired := false

	go func() {
		lock2, err := newFileLock(tmpFile.Name())
		if err != nil {
			return
		}
		_ = lock2.Lock()
		mu.Lock()
		acquired = true
		mu.Unlock()
		_ = lock2.Unlock()
	}()

	// Give the goroutine time to attempt the lock
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	assert.False(t, acquired, "second lock should be blocked while first is held")
	mu.Unlock()

	// Release first lock
	err = lock1.Unlock()
	assert.NoError(t, err)

	// Wait for second lock to acquire
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	assert.True(t, acquired, "second lock should acquire after first is released")
	mu.Unlock()

	// Clean up lock file
	os.Remove(lockFilePath(tmpFile.Name()))
}
