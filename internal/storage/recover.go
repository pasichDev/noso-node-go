package storage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RecoverDataDir removes the debris of interrupted writes below root: *.new
// (staged, never committed) and *.tmp (atomic write interrupted). A wallet
// temporary holds clear-text or sealed keys and is overwritten before removal.
// LockDataDir calls it after taking the lock.
//
// FIX(F-13): there is no multi-file transaction manifest any more. The node
// never used one (its chain changes go through its own journal, which is bound
// to the chain it was written for, node/commit.go), and a manifest in the data
// directory was a way for a planted file to replace files outside the root or
// to stop every start. A link is never followed (FIX(F-14)): a link with a
// temporary name is removed as a link and its target is left alone.
func RecoverDataDir(root string) error {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		stray := strings.HasSuffix(p, ".new") || strings.HasSuffix(p, ".tmp")
		switch {
		case !stray:
		case d.Type()&fs.ModeSymlink != 0:
			_ = os.Remove(p)
		case strings.HasSuffix(p, ".tmp") && strings.Contains(filepath.Base(p), "wallet"):
			_ = shred(p)
		default:
			_ = os.Remove(p)
		}
		return nil
	})
	return nil
}
