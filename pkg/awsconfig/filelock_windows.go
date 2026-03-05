package awsconfig

import (
	"os"

	"golang.org/x/sys/windows"
)

type windowsFileLock struct {
	f *os.File
}

func newFileLock(path string) (fileLock, error) {
	f, err := os.OpenFile(lockFilePath(path), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	return &windowsFileLock{f: f}, nil
}

func (l *windowsFileLock) Lock() error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(l.f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}

func (l *windowsFileLock) Unlock() error {
	ol := new(windows.Overlapped)
	defer l.f.Close()
	return windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
}
