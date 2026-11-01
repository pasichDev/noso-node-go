package storage

import (
	"os"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// GVTBaseValue is nosogvts.pas:30.
const GVTBaseValue = 70000000000

// FundsAddress is the project funds address (masterpaskalform.pas:558).
const FundsAddress = "NpryectdevepmentfundsGE"

// GVTs is gvts.psk, a flat file of 105-byte GVT records.
type GVTs struct {
	mu   sync.Mutex
	path string
	arr  []types.GVT
	hash string
}

// OpenGVTs mirrors the VerifyFiles sequence: create when missing, then
// GetGVTsFileData.
func OpenGVTs(path string) *GVTs {
	g := &GVTs{path: path}
	if !Exists(path) {
		_ = writeFileAtomic(path, nil)
	}
	g.Reload()
	return g
}

// Path returns the file path.
func (g *GVTs) Path() string { return g.path }

// Reload mirrors GetGVTsFileData.
func (g *GVTs) Reload() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.arr = nil
	if raw, err := os.ReadFile(g.path); err == nil {
		n := len(raw) / types.GVTSize
		for i := 0; i < n; i++ {
			g.arr = append(g.arr, types.DecodeGVT(raw[i*types.GVTSize:]))
		}
	}
	g.hash = crypto.IDHashFile(g.path)
}

// Save mirrors SaveGVTs. The error is not optional to look at: a failed write
// leaves the file (and Hash) out of step with the in-memory records.
func (g *GVTs) Save() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []byte
	for _, r := range g.arr {
		out = append(out, r.Encode()...)
	}
	err := writeFileAtomic(g.path, out)
	g.hash = crypto.IDHashFile(g.path)
	return err
}

// Hash returns MyGVTsHash.
func (g *GVTs) Hash() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hash
}

// Bytes returns the file content (GetGVTsAsStream).
func (g *GVTs) Bytes() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return os.ReadFile(g.path)
}

// Replace stores a downloaded file (SaveStreamAsGVTs) and refreshes the hash.
func (g *GVTs) Replace(data []byte) bool {
	g.mu.Lock()
	err := writeFileAtomic(g.path, data)
	g.hash = crypto.IDHashFile(g.path)
	g.mu.Unlock()
	return err == nil
}

// Len mirrors GetGVTLength.
func (g *GVTs) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.arr)
}

// Index mirrors GetGVTIndex: the default (zero) record when out of range.
func (g *GVTs) Index(i int) types.GVT {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i > len(g.arr)-1 || i < 0 {
		return types.GVT{}
	}
	return g.arr[i]
}

// All returns a copy of every record.
func (g *GVTs) All() []types.GVT {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]types.GVT(nil), g.arr...)
}

// ChangeOwner mirrors ChangeGVTOwner (nosogvts.pas:160-175). Result codes:
// 0 ok, 1 number above 99, 2 old owner mismatch, 3 invalid new owner.
// Negative numbers are rejected with 1 (hardening: Pascal would index
// outside the array).
func (g *GVTs) ChangeOwner(n int, oldOwner, newOwner string) int {
	res := 0
	if n > 99 || n < 0 {
		res = 1
	}
	cur := g.Index(n)
	if cur.Owner != oldOwner {
		res = 2
	}
	if !crypto.IsValidHashAddress(newOwner) {
		res = 3
	}
	if res == 0 {
		g.mu.Lock()
		if n < len(g.arr) {
			g.arr[n].Owner = codec.Truncate(newOwner, 32) // String[32]
		}
		g.mu.Unlock()
	}
	return res
}

// CountAvailable mirrors CountAvailableGVTs.
func (g *GVTs) CountAvailable() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := 0
	for _, r := range g.arr {
		if r.Owner == FundsAddress {
			c++
		}
	}
	return c
}

// GVTPrice mirrors GetGVTPrice (nosogvts.pas:188-198) with Int64 integer
// arithmetic and truncating division.
func GVTPrice(available int, toSell bool) int64 {
	r := int64(GVTBaseValue)
	for i := 1; i <= 40-available; i++ {
		r = r * 110 / 100
	}
	if r < GVTBaseValue {
		r = GVTBaseValue
	}
	if toSell {
		r = r * 85 / 100
	}
	return r
}

// Backup / RestoreBackup mirror the .bak handling of BuildNewBlock and
// UndoneLastBlock. Both copy atomically: a missing gvts.psk does not delete the
// good .bak, and a missing .bak does not delete gvts.psk (re2 #7).
func (g *GVTs) Backup() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return copyFile(g.path, g.path+".bak")
}

// RestoreBackup copies gvts.psk.bak back and reloads.
func (g *GVTs) RestoreBackup() error {
	g.mu.Lock()
	err := copyFile(g.path+".bak", g.path)
	g.mu.Unlock()
	g.Reload()
	return err
}
