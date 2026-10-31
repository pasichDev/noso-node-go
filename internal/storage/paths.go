// Package storage reads and writes every file of the NOSODATA directory
// with the exact formats of the Pascal node.
package storage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
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
func (l Layout) EnsureDirs() int {
	failed := 0
	for _, d := range []string{l.Root, l.LogsDir, l.BlockDir, l.UpdatesDir, l.MarksDir,
		l.GVTMarksDir, l.RPCBakDir, l.DBDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			failed++
		}
	}
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

// writeFileAtomic writes data to path via a temporary file and rename so a
// crash cannot leave a half written file (hardening; the resulting bytes
// are identical to the Pascal SaveToFile).
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// copyFile mirrors TryCopyFile.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
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
