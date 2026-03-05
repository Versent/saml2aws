package awsconfig

// fileLock provides mutual exclusion for file access across processes.
type fileLock interface {
	Lock() error
	Unlock() error
}

// lockFilePath returns the lock file path for a given file.
func lockFilePath(path string) string {
	return path + ".lck"
}
