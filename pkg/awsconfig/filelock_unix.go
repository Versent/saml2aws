//go:build !windows
// +build !windows

package awsconfig

import (
	"os"

	"golang.org/x/sys/unix"
)

type unixFileLock struct {
	f *os.File
}

func newFileLock(path string) (fileLock, error) {
	f, err := os.OpenFile(lockFilePath(path), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return &unixFileLock{f: f}, nil
}

func (l *unixFileLock) Lock() error {
	return unix.Flock(int(l.f.Fd()), unix.LOCK_EX)
}

func (l *unixFileLock) Unlock() error {
	defer l.f.Close()
	return unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
}
