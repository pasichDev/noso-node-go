//go:build !windows

package control

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a socket directory that is not ours or is open to
// others.
func checkOwner(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Getuid() || fi.Mode().Perm()&0o077 != 0 || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("control: %s is not a private directory of this user", dir)
	}
	return nil
}
