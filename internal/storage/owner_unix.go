//go:build unix

package storage

import (
	"os"
	"syscall"
)

// ownedByUs reports whether the directory belongs to the user running the
// process (or to nobody we can tell, when the platform gives no owner).
func ownedByUs(st os.FileInfo) bool {
	if os.Geteuid() == 0 {
		return true // root may use any directory
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid) == os.Geteuid()
	}
	return true
}
