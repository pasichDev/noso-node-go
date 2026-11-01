package storage

import (
	"os"
	"sync/atomic"
)

var noSync atomic.Bool

// SetNoSyncForTests turns off fsync for the chain files (blocks, headers,
// summary, snapshots, journal). It exists so a test can build thousands of
// blocks from genesis without a disk flush each; validation and every other
// step are unchanged. Wallet files always sync. Never call it outside tests.
func SetNoSyncForTests(on bool) { noSync.Store(on) }

// NoSync reports whether the test-only mode is on.
func NoSync() bool { return noSync.Load() }

func syncFile(f *os.File) error {
	if noSync.Load() {
		return nil
	}
	return f.Sync()
}
