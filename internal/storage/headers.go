package storage

import (
	"os"
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Headers is blchhead.nos: a flat file of 70-byte ResumenData records, one
// per block starting at block 0 (nosoheaders.pas).
type Headers struct {
	mu   sync.Mutex
	path string
	hash string
}

// OpenHeaders mirrors SetHeadersFileName: the file is created empty when
// missing and its MD5 cached.
func OpenHeaders(path string) *Headers {
	h := &Headers{path: path}
	if !Exists(path) {
		_ = os.WriteFile(path, nil, 0o644)
	}
	h.hash = crypto.MD5File(path)
	return h
}

// Path returns the file path.
func (h *Headers) Path() string { return h.path }

// SetHash recomputes the cached MD5 (SetResumenHash).
func (h *Headers) SetHash() {
	h.mu.Lock()
	h.hash = crypto.MD5File(h.path)
	h.mu.Unlock()
}

// Hash returns the cached MD5 (GetResumenHash).
func (h *Headers) Hash() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hash
}

// Create truncates the file (CreateHeadersFile).
func (h *Headers) Create() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return os.WriteFile(h.path, nil, 0o644) == nil
}

// Add appends a record (AddRecordToHeaders).
func (h *Headers) Add(block int64, blockHash, sumHash string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, err := os.OpenFile(h.path, os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	// COMPAT: BlockNumber is Int64 but the record field is a 32-bit integer.
	_, err = f.Write(types.Resumen{Block: int32(block), BlockHash: blockHash, SumHash: sumHash}.Encode())
	return err == nil
}

// RemoveLast drops the final record (RemoveHeadersLastRecord).
func (h *Headers) RemoveLast() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := os.Stat(h.path)
	if err != nil {
		return false
	}
	n := st.Size() / types.ResumenSize
	if n == 0 {
		return false // seek(-1) raises in Pascal
	}
	return os.Truncate(h.path, (n-1)*types.ResumenSize) == nil
}

// Height mirrors GetHeadersHeigth: record count minus one, -1 on error.
func (h *Headers) Height() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := os.Stat(h.path)
	if err != nil {
		return -1
	}
	return int(st.Size()/types.ResumenSize) - 1
}

func (h *Headers) readAll() []types.Resumen {
	raw, err := os.ReadFile(h.path)
	if err != nil {
		return nil
	}
	n := len(raw) / types.ResumenSize
	out := make([]types.Resumen, n)
	for i := 0; i < n; i++ {
		out[i] = types.DecodeResumen(raw[i*types.ResumenSize:])
	}
	return out
}

// All returns every record.
func (h *Headers) All() []types.Resumen {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.readAll()
}

// LastBlock mirrors GetHeadersLastBlock: block field of the last record,
// 0 when empty.
func (h *Headers) LastBlock() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastBlockLocked()
}

func (h *Headers) lastBlockLocked() int {
	all := h.readAll()
	if len(all) == 0 {
		return 0
	}
	return int(all[len(all)-1].Block)
}

// Bytes returns the file content (GetHeadersAsMemStream).
func (h *Headers) Bytes() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return os.ReadFile(h.path)
}

// Replace stores a downloaded headers file (SaveStreamAsHeaders).
func (h *Headers) Replace(data []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return writeFileAtomic(h.path, data) == nil
}

// LastHeadersString mirrors nosoheaders.pas:237-266. COMPAT: it starts at
// record index FromBlock-100 (line 250) and refuses when FromBlock is more
// than 1008 below the last block; a negative start makes Pascal's seek
// raise, which is swallowed and yields an empty answer.
func (h *Headers) LastHeadersString(fromBlock int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fromBlock < h.lastBlockLocked()-1008 {
		return ""
	}
	start := fromBlock - 100
	if start < 0 {
		return ""
	}
	all := h.readAll()
	var sb strings.Builder
	for i := start; i < len(all); i++ {
		sb.WriteString(codec.IntToStr(int64(all[i].Block)) + ":" + all[i].BlockHash + ":" + all[i].SumHash + " ")
	}
	return codec.Trim(sb.String())
}
