package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// ErrDataDirLocked is returned by LockDataDir when another process (or
// another handle in this one) holds the data directory.
var ErrDataDirLocked = errors.New("storage: data directory is in use by another process")

// DirLock is an exclusive, cross-process lock on a data directory (flock on
// Unix, LockFileEx on Windows). The operating system releases it when the
// process dies, so a crash never leaves a stale lock.
type DirLock struct {
	f *os.File
}

// LockDataDir takes the exclusive lock of the data directory root (creating
// it 0700 if needed) without waiting, then finishes or discards what a crash
// left behind (RecoverDataDir). Every process that writes the data directory
// must hold the lock for its whole lifetime: nosod, the GUI, and nosocli when
// it opens the directory itself instead of talking to the control socket. A
// second holder gets ErrDataDirLocked. The lock file is root/.lock; it is
// never removed.
func LockDataDir(root string) (*DirLock, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(root, ".lock")
	// FIX(F-14): the lock file is never a link, so opening it cannot truncate
	// (below) a file somewhere else.
	pre, lerr := os.Lstat(p)
	if lerr == nil && !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("storage: %s is not a regular file; remove it", p)
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if st, serr := f.Stat(); serr != nil || !st.Mode().IsRegular() || (lerr == nil && !os.SameFile(pre, st)) {
		_ = f.Close()
		return nil, fmt.Errorf("storage: %s changed while it was being opened", p)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if isLockBusy(err) {
			return nil, fmt.Errorf("%w (%s)", ErrDataDirLocked, p)
		}
		return nil, err
	}
	l := &DirLock{f: f}
	if err := RecoverDataDir(root); err != nil {
		_ = l.Close()
		return nil, err
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0) // diagnostics only
	return l, nil
}

// Close releases the lock.
func (l *DirLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = unlockFile(l.f)
	err := l.f.Close()
	l.f = nil
	return err
}
