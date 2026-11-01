//go:build !unix && !windows

package storage

import (
	"errors"
	"os"
)

func lockFile(f *os.File) error {
	return errors.New("storage: data directory locking is not supported on this platform")
}
func unlockFile(f *os.File) error { return nil }
func isLockBusy(err error) bool   { return false }
