//go:build !unix

package storage

import "os"

// ownedByUs: on these platforms the directory inherits the ACL of its parent
// and there is no owner to compare (see EnsureDirs).
func ownedByUs(st os.FileInfo) bool { return true }
