// Package storage reads and writes every file of the NOSODATA directory
// with the exact formats of the Pascal node.
package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
)

// Layout holds every path of a node data directory (masterpaskalform.pas
// :804-820, mpdisk.pas:66-85). The directory defaults to "NOSODATA".
type Layout struct {
	Root         string
	BlockDir     string // NOSODATA/BLOCKS/
	DBDir        string // NOSODATA/BLOCKS/DB/
	LogsDir      string
	UpdatesDir   string
	MarksDir     string
	GVTMarksDir  string
	RPCBakDir    string
	Summary      string // sumary.psk
	SummaryZip   string // sumary.zip
	Headers      string // blchhead.nos
	GVTs         string // gvts.psk
	CFG          string // nosocfg.psk
	Masternodes  string // masternodes.txt
	Wallet       string // wallet.pkw
	PSOs         string // psos.dat
	AdvOpt       string // advopt.txt
	BlocksDB     string // blocks_db.nos
	ClosedMarker string // LOGS/proclo.dat
}

// NewLayout builds a Layout rooted at root.
func NewLayout(root string) Layout {
	j := filepath.Join
	l := Layout{Root: root}
	l.BlockDir = j(root, "BLOCKS")
	l.DBDir = j(l.BlockDir, "DB")
	l.LogsDir = j(root, "LOGS")
	l.UpdatesDir = j(root, "UPDATES")
	l.MarksDir = j(root, "SUMMARKS")
	l.GVTMarksDir = j(l.MarksDir, "GVTS")
	l.RPCBakDir = j(l.MarksDir, "RPC")
	l.Summary = j(root, "sumary.psk")
	l.SummaryZip = j(root, "sumary.zip")
	l.Headers = j(root, "blchhead.nos")
	l.GVTs = j(root, "gvts.psk")
	l.CFG = j(root, "nosocfg.psk")
	l.Masternodes = j(root, "masternodes.txt")
	l.Wallet = j(root, "wallet.pkw")
	l.PSOs = j(root, "psos.dat")
	l.AdvOpt = j(root, "advopt.txt")
	l.BlocksDB = j(l.DBDir, "blocks_db.nos")
	l.ClosedMarker = j(l.LogsDir, "proclo.dat")
	return l
}

// BlockFile returns the path of block n (mpblock.pas:152: N.blk).
func (l Layout) BlockFile(n int64) string {
	return filepath.Join(l.BlockDir, itoa(n)+".blk")
}

// EnsureDirs mirrors FileStructure (mpdisk.pas:66-85); it returns the
// number of directories that could not be created.
//
// FIX(re2 #8): the data directory is created 0700 and an existing one is
// tightened to 0700, because it holds the wallet and the RPC tokens. On
// Windows neither the mode nor os.Chmod does anything: the directory inherits
// the ACL of its parent, so put the data directory below the user's profile
// (the default) or set the ACL by hand (icacls <dir> /inheritance:r /grant:r
// "%USERNAME%:(OI)(CI)F"). The node does not set a DACL itself.
func (l Layout) EnsureDirs() int {
	failed := 0
	for _, d := range []string{l.Root, l.LogsDir, l.BlockDir, l.UpdatesDir, l.MarksDir,
		l.GVTMarksDir, l.RPCBakDir, l.DBDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			failed++
		}
	}
	_ = os.Chmod(l.Root, 0o700)
	return failed
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	var b [20]byte
	i := len(b)
	u := uint64(n)
	if neg {
		u = uint64(-n)
	}
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// WriteFileAtomic replaces path with data so that after a crash the file is
// either the old content or the new content, never a mix, and the new content
// is on stable storage when it returns nil: temporary file, fsync, rename,
// fsync of the directory. The result has mode 0600 (an existing file's mode is
// replaced, which also tightens a Pascal-era 0644 file). Every state file of
// the node is written through this function; code outside the package must use
// it too (node/chain.go snapshot).
func WriteFileAtomic(path string, data []byte) error { return writeFileAtomic(path, data) }

// atomicLocks serialises writers of one path inside the process: two writers
// would share the same temporary file.
var atomicLocks sync.Map

func writeFileAtomic(path string, data []byte) error {
	m, _ := atomicLocks.LoadOrStore(path, &sync.Mutex{})
	m.(*sync.Mutex).Lock()
	defer m.(*sync.Mutex).Unlock()
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600) // a stale tmp may have been created with another mode
	_, werr := f.Write(data)
	if serr := f.Sync(); werr == nil { // FIX(M-12): flush before the rename
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // FIX(re2 #14): in plain wallet mode this is a clear-text copy
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir flushes a directory entry change (rename, create, remove). Windows
// cannot fsync a directory handle and persists the rename itself; filesystems
// that reject directory fsync with EINVAL are tolerated.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, syscall.EINVAL) {
		return nil
	}
	return err
}

// copyFile mirrors TryCopyFile, atomically: the destination is replaced as a
// whole (see WriteFileAtomic) and left untouched when the source cannot be
// read. Used for every .bak copy.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b)
}

// Exists reports whether path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// fileLocks serialises access per path like the Pascal critical sections.
var fileLocks sync.Map

func lockFor(path string) *sync.Mutex {
	m, _ := fileLocks.LoadOrStore(path, &sync.Mutex{})
	return m.(*sync.Mutex)
}
