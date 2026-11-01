package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// PSOHdrBytes is the size of the PSO file header.
const PSOHdrBytes = 12

// MNsLockExpireLapse is nosopsos.pas:67.
const MNsLockExpireLapse = 2016

// PSO is TPSOData. Only the file format is consensus relevant: no live
// code path of the node creates PSOs besides AddNewPSO.
type PSO struct {
	Mode    uint16
	Hash    string
	Owner   string
	Expire  int32 // DWord in the record, but Integer in Pascal: FFFFFFFF reads as -1
	Members string
	Params  string
}

// PSOHeader is TPSOHeader.
type PSOHeader struct{ Block, MNsLock, Count int32 }

// PSOs is psos.dat: header, locked masternodes, then PSO records whose
// strings are Word length prefixed (TStreamHelper.SetString).
type PSOs struct {
	mu     sync.Mutex
	path   string
	header PSOHeader
	locks  []types.MNLock
	psos   []PSO
	hash   string
	// saveErr is the result of the last write of the file.
	saveErr error
}

// OpenPSOs mirrors LoadPSOFileFromDisk at startup.
func OpenPSOs(path string) *PSOs {
	p := &PSOs{path: path}
	p.Load()
	return p
}

// Path returns the file path.
func (p *PSOs) Path() string { return p.path }

// Load mirrors LoadPSOFileFromDisk (nosopsos.pas:138-203). It returns the
// (inverted-sense) COMPAT flag of the Pascal function: true when the file
// was unreadable.
func (p *PSOs) Load() (errored bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.header, p.locks, p.psos = PSOHeader{}, nil, nil
	raw, err := os.ReadFile(p.path)
	if err == nil && len(raw) > 0 {
		errored = !p.parse(raw)
	}
	if !Exists(p.path) || errored {
		p.saveLocked(int(p.header.Block))
	} else {
		p.hash = crypto.IDHashFile(p.path)
	}
	return errored
}

func (p *PSOs) parse(raw []byte) bool {
	r := bytes.NewReader(raw)
	var h [3]int32
	if binary.Read(r, binary.LittleEndian, &h) != nil {
		return false
	}
	p.header = PSOHeader{h[0], h[1], h[2]}
	// FIX(M-09): the counts must fit the file before anything is allocated or
	// looped over (nosopsos.pas:159-197 trusted them and ignored read results).
	if h[1] < 0 || h[2] < 0 || int64(h[1])*types.MNLockSize > int64(len(raw)-PSOHdrBytes) ||
		int64(h[2])*14 > int64(len(raw)-PSOHdrBytes)-int64(h[1])*types.MNLockSize {
		return false
	}
	for i := int32(0); i < h[1]; i++ {
		var b [types.MNLockSize]byte
		if _, err := io.ReadFull(r, b[:]); err != nil { // ReadBuffer raises on a short read
			return false
		}
		p.locks = append(p.locks, types.DecodeMNLock(b[:]))
	}
	str := func() (string, bool) {
		var n uint16
		if binary.Read(r, binary.LittleEndian, &n) != nil {
			return "", false
		}
		s := make([]byte, n)
		if _, err := io.ReadFull(r, s); err != nil && n > 0 {
			return "", false
		}
		return string(s), true
	}
	for i := int32(0); i < h[2]; i++ {
		var rec PSO
		var ok bool
		if binary.Read(r, binary.LittleEndian, &rec.Mode) != nil {
			return false
		}
		if rec.Hash, ok = str(); !ok {
			return false
		}
		if rec.Owner, ok = str(); !ok {
			return false
		}
		if binary.Read(r, binary.LittleEndian, &rec.Expire) != nil {
			return false
		}
		if rec.Members, ok = str(); !ok {
			return false
		}
		if rec.Params, ok = str(); !ok {
			return false
		}
		p.psos = append(p.psos, rec)
	}
	return true
}

// Save mirrors SavePSOFileToDisk (nosopsos.pas:205-240).
func (p *PSOs) Save(block int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveLocked(block)
}

// saveLocked writes the file; the error of the last write is kept for SaveErr.
func (p *PSOs) saveLocked(block int) error {
	p.header.Block = int32(block)
	p.header.Count = int32(len(p.psos))
	p.header.MNsLock = int32(len(p.locks))
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, [3]int32{p.header.Block, p.header.MNsLock, p.header.Count})
	for _, l := range p.locks {
		b.Write(l.Encode())
	}
	str := func(s string) {
		// COMPAT: the length is a 16-bit Word (nosogeneral.pas:106-111).
		_ = binary.Write(&b, binary.LittleEndian, uint16(len(s)))
		b.WriteString(s[:int(uint16(len(s)))])
	}
	for _, r := range p.psos {
		_ = binary.Write(&b, binary.LittleEndian, r.Mode)
		str(r.Hash)
		str(r.Owner)
		_ = binary.Write(&b, binary.LittleEndian, r.Expire)
		str(r.Members)
		str(r.Params)
	}
	p.saveErr = writeFileAtomic(p.path, b.Bytes())
	p.hash = crypto.IDHashFile(p.path)
	return p.saveErr
}

// SaveErr returns the error of the most recent write of psos.dat (nil when it
// succeeded). Methods that save as a side effect (AddLocked, AddNew, Load,
// ClearExpired) keep their signatures; a caller that must not advance on a
// failed write checks this afterwards (re2 #7).
func (p *PSOs) SaveErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveErr
}

// FileHash returns PSOFileHash.
func (p *PSOs) FileHash() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hash
}

// Header returns the cached header.
func (p *PSOs) Header() PSOHeader {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.header
}

// Bytes returns the file content (GetPSOsAsMemStream).
func (p *PSOs) Bytes() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return os.ReadFile(p.path)
}

// Replace stores a downloaded file (SavePSOsToFile) without reloading.
func (p *PSOs) Replace(data []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return writeFileAtomic(p.path, data) == nil
}

// Locked masternodes (nosopsos.pas:274-369).

// LockedCount mirrors GetLockedMNsCount.
func (p *PSOs) LockedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.locks)
}

// LockedAt mirrors GetLockedMNIndex.
func (p *PSOs) LockedAt(i int) types.MNLock {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= 0 && i < len(p.locks) {
		return p.locks[i]
	}
	return types.MNLock{}
}

// AddLocked mirrors AddLockedMM: the address is locked for 2016 blocks.
func (p *PSOs) AddLocked(addr string, block int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.locks {
		if l.Address == addr {
			return false
		}
	}
	p.locks = append(p.locks, types.MNLock{
		Address: codec.Truncate(addr, 32), Expire: int32(block + MNsLockExpireLapse)})
	return true
}

// ClearExpired mirrors ClearExpiredLockedMNs.
func (p *PSOs) ClearExpired(block int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	out := p.locks[:0]
	for _, l := range p.locks {
		if int(l.Expire) <= block {
			n++
			continue
		}
		out = append(out, l)
	}
	p.locks = out
	return n
}

// IsLocked mirrors IsLockedMN.
func (p *PSOs) IsLocked(addr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, l := range p.locks {
		if l.Address == addr {
			return true
		}
	}
	return false
}

// LockedRaw mirrors LockedMNsRawString. COMPAT: the Pascal `Trim(Result)`
// at line 368 discards its value, so the trailing blank is kept.
func (p *PSOs) LockedRaw() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sb strings.Builder
	for _, l := range p.locks {
		sb.WriteString(l.Address + "," + codec.IntToStr(int64(l.Expire)) + " ")
	}
	return sb.String()
}

// Value mirrors GetPSOValue (nosopsos.pas:393-413).
func PSOValue(label, params string) string {
	params = strings.ReplaceAll(params, ";", " ")
	for i := int64(0); ; i++ {
		item := codec.Parameter(params, i)
		if item == "" {
			return ""
		}
		item = strings.ReplaceAll(item, ":", " ")
		if codec.Parameter(item, 0) == label {
			return codec.Parameter(item, 1)
		}
	}
}

// AddNew mirrors AddNewPSO.
func (p *PSOs) AddNew(mode int, owner string, expire int, params string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.psos = append(p.psos, PSO{Mode: uint16(mode), Owner: owner, Expire: int32(expire),
		Hash:   crypto.IDHash(owner + params + codec.IntToStr(int64(mode))),
		Params: params})
}

// All returns a copy of the PSO list (GetPSOsCopy).
func (p *PSOs) All() []PSO {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PSO(nil), p.psos...)
}

var errShort = errors.New("short psos file")

var _ = errShort

// ValidPSOFile reports whether data is a complete, consistent PSO file. It
// is used to vet a downloaded file before it replaces the local one.
// FIX(H-06, M-09).
func ValidPSOFile(data []byte) bool {
	p := &PSOs{}
	return len(data) >= PSOHdrBytes && p.parse(data)
}
