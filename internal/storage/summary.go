package storage

import (
	"os"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// GenesisAddress is the account that receives the premine and whose
// LastOP field doubles as the summary's last block (nosounit.pas:132).
const GenesisAddress = "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"

// Premine is PremineAmount (masterpaskalform.pas:592).
const Premine = 1030390730000

type blockRec struct {
	slot int64
	rec  types.Summary
}

// SummaryDB is the sumary.psk account database plus the per block "block
// records" scratch list of nosounit.pas. All methods are goroutine safe.
type SummaryDB struct {
	mu      sync.Mutex
	path    string
	recs    []types.Summary
	byHash  map[string]int64 // first slot per stored Hash
	byAlias map[string]int64 // first slot per Custom, see COMPAT in addIndex
	block   []blockRec
	brHash  map[string]int
	lastOp  int64
	hash    string
}

// OpenSummary loads (without creating) the summary at path. A missing file
// yields an empty database, like an index built over an empty file.
func OpenSummary(path string) *SummaryDB {
	s := &SummaryDB{path: path}
	s.rebuildIndexLocked()
	return s
}

// Path returns the file path.
func (s *SummaryDB) Path() string { return s.path }

func (s *SummaryDB) rebuildIndexLocked() {
	s.recs = nil
	s.byHash = map[string]int64{}
	s.byAlias = map[string]int64{}
	if raw, err := os.ReadFile(s.path); err == nil {
		n := len(raw) / types.SummarySize
		s.recs = make([]types.Summary, 0, n)
		for i := 0; i < n; i++ {
			r := types.DecodeSummary(raw[i*types.SummarySize : (i+1)*types.SummarySize])
			s.recs = append(s.recs, r)
			s.addIndex(r, int64(i))
		}
	}
	s.lastOp = 0
	if len(s.recs) > 0 {
		s.lastOp = s.recs[0].LastOP
	}
	s.hash = crypto.MD5File(s.path)
}

func (s *SummaryDB) addIndex(r types.Summary, slot int64) {
	if _, ok := s.byHash[r.Hash]; !ok {
		s.byHash[r.Hash] = slot
	}
	if r.Custom != "" {
		if _, ok := s.byAlias[r.Custom]; !ok {
			s.byAlias[r.Custom] = slot
		}
	}
}

// CreateIndex re-reads the file (CreateSumaryIndex, nosounit.pas:279-312).
func (s *SummaryDB) CreateIndex() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildIndexLocked()
}

// CreateNew mirrors CreateNewSummaryFile (nosounit.pas:121-141).
func (s *SummaryDB) CreateNew(addBlockZero bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.WriteFile(s.path, nil, 0o644)
	s.rebuildIndexLocked()
	// Hardening: Pascal keeps stale block records here, which would be
	// written at slots beyond the new empty file.
	s.block, s.brHash = nil, nil
	if addBlockZero {
		s.creditLocked(GenesisAddress, Premine, 0)
		s.updateChangesLocked()
		s.block = nil
		s.brHash = nil
		s.lastOp = 0
	}
	s.hash = crypto.MD5File(s.path)
}

// Hash returns the cached MD5 of the file (MySumarioHash).
func (s *SummaryDB) Hash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hash
}

// SetHash recomputes the cached MD5 (SetSummaryHash).
func (s *SummaryDB) SetHash() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hash = crypto.MD5File(s.path)
}

// LastOp returns SummaryLastop.
func (s *SummaryDB) LastOp() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastOp
}

// SetLastOp assigns SummaryLastop (BuildNewBlock does it explicitly).
func (s *SummaryDB) SetLastOp(v int64) {
	s.mu.Lock()
	s.lastOp = v
	s.mu.Unlock()
}

// Len returns the number of records on file.
func (s *SummaryDB) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

// At returns the committed record at slot.
func (s *SummaryDB) At(slot int) (types.Summary, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot < 0 || slot >= len(s.recs) {
		return types.Summary{}, false
	}
	return s.recs[slot], true
}

// All returns a copy of every committed record.
func (s *SummaryDB) All() []types.Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]types.Summary(nil), s.recs...)
}

func (s *SummaryDB) lookupLocked(text string, isAlias bool) (int64, types.Summary) {
	m := s.byHash
	if isAlias {
		m = s.byAlias
	}
	if slot, ok := m[text]; ok {
		return slot, s.recs[slot]
	}
	return -1, types.Summary{}
}

// GetIndexPosition mirrors nosounit.pas:323-347. It returns the disk slot
// or -1. COMPAT: the alias index is only extended when NEW records are
// appended or when the index is rebuilt (UpdateSummaryChanges never
// re-indexes an existing record whose alias changed), so a freshly
// customised account is not found by alias until CreateIndex runs.
func (s *SummaryDB) GetIndexPosition(text string, isAlias bool) (int64, types.Summary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupLocked(text, isAlias)
}

// BalanceIndexed mirrors GetAddressBalanceIndexed (nosounit.pas:350-373).
func (s *SummaryDB) BalanceIndexed(addr string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, ok := s.byHash[addr]; ok {
		return s.recs[slot].Balance
	}
	return 0
}

// Alias mirrors GetAddressAlias (nosounit.pas:560-568).
func (s *SummaryDB) Alias(addr string) string {
	slot, r := s.GetIndexPosition(addr, false)
	if slot >= 0 && r.Custom != "" {
		return r.Custom
	}
	return ""
}

// AddressLastOP mirrors GetAddressLastOP.
func (s *SummaryDB) AddressLastOP(addr string) int64 {
	slot, r := s.GetIndexPosition(addr, false)
	if slot >= 0 {
		return r.LastOP
	}
	return 0
}

// ResetBlockRecords mirrors ResetBlockRecords.
func (s *SummaryDB) ResetBlockRecords() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block, s.brHash = nil, nil
}

func (s *SummaryDB) insBlock(r types.Summary, slot int64) {
	if s.brHash == nil {
		s.brHash = map[string]int{}
	}
	s.block = append(s.block, blockRec{slot, r})
	if _, ok := s.brHash[r.Hash]; !ok {
		s.brHash[r.Hash] = len(s.block) - 1
	}
}

func (s *SummaryDB) findBlock(addr string) int {
	if i, ok := s.brHash[addr]; ok {
		return i
	}
	return -1
}

// ValidPay mirrors SummaryValidPay (nosounit.pas:394-432).
func (s *SummaryDB) ValidPay(addr string, amount, blockNumber int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validPayLocked(addr, amount, blockNumber)
}

func (s *SummaryDB) validPayLocked(addr string, amount, blockNumber int64) bool {
	if i := s.findBlock(addr); i >= 0 {
		if s.block[i].rec.Balance < amount {
			return false
		}
		s.block[i].rec.Balance -= amount
		s.block[i].rec.LastOP = blockNumber
		return true
	}
	slot, r := s.lookupLocked(addr, false)
	if slot < 0 {
		return false
	}
	if r.Balance < amount {
		return false
	}
	r.Balance -= amount
	r.LastOP = blockNumber
	s.insBlock(r, slot)
	return true
}

// Pay mirrors SummaryPay (nosounit.pas:434-463): no balance check; an
// unknown address is silently ignored.
func (s *SummaryDB) Pay(addr string, amount, blockNumber int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payLocked(addr, amount, blockNumber)
}

func (s *SummaryDB) payLocked(addr string, amount, blockNumber int64) {
	if i := s.findBlock(addr); i >= 0 {
		s.block[i].rec.Balance -= amount
		s.block[i].rec.LastOP = blockNumber
		return
	}
	slot, r := s.lookupLocked(addr, false)
	if slot < 0 {
		return
	}
	r.Balance -= amount
	r.LastOP = blockNumber
	s.insBlock(r, slot)
}

// CreditTo mirrors nosounit.pas:466-491. COMPAT: the receiver is never
// validated, and an over-long address is stored truncated to String[40],
// so later lookups with the full string miss and create another record.
func (s *SummaryDB) CreditTo(addr string, amount, blockNumber int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creditLocked(addr, amount, blockNumber)
}

func (s *SummaryDB) creditLocked(addr string, amount, blockNumber int64) {
	if i := s.findBlock(addr); i >= 0 {
		s.block[i].rec.Balance += amount
		s.block[i].rec.LastOP = blockNumber
		return
	}
	slot, r := s.lookupLocked(addr, false)
	r.Balance += amount
	r.LastOP = blockNumber
	if slot < 0 {
		r.Hash = codec.Truncate(addr, 40)
	}
	s.insBlock(r, slot)
}

// CustomizationValid mirrors IsCustomizacionValid (nosounit.pas:494-526).
// COMPAT: the fee is the literal 25000 (not GetCustFee), and the already
// pending branch (lines 505-512) does not update LastOP while the disk
// branch does.
func (s *SummaryDB) CustomizationValid(addr, custom string, blockNumber int64, force bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.findBlock(addr); i >= 0 {
		r := &s.block[i].rec
		if r.Custom != "" && !force {
			return false
		}
		if r.Balance < 25000 && !force {
			return false
		}
		r.Custom = custom
		r.Balance -= 25000
		return true
	}
	slot, r := s.lookupLocked(addr, false)
	if slot < 0 {
		return false
	}
	if r.Balance < 25000 && !force {
		return false
	}
	if r.Custom != "" && !force {
		return false
	}
	r.Custom = custom
	r.Balance -= 25000
	r.LastOP = blockNumber
	s.insBlock(r, slot)
	return true
}

// UpdateChanges mirrors UpdateSummaryChanges (nosounit.pas:529-557): the
// block records are written to their slots (new ones appended) and the
// cached hash and last operation are refreshed.
func (s *SummaryDB) UpdateChanges() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateChangesLocked()
}

func (s *SummaryDB) updateChangesLocked() {
	f, err := os.OpenFile(s.path, os.O_RDWR, 0o644)
	if err == nil {
		defer f.Close()
		for i := range s.block {
			b := &s.block[i]
			if b.slot < 0 {
				b.slot = int64(len(s.recs))
				s.recs = append(s.recs, b.rec)
				s.addIndex(b.rec, b.slot)
			} else {
				for int64(len(s.recs)) <= b.slot { // the file grows with zero records
					s.recs = append(s.recs, types.Summary{})
				}
				s.recs[b.slot] = b.rec
			}
			_, _ = f.WriteAt(b.rec.Encode(), b.slot*types.SummarySize)
		}
	}
	s.lastOp = 0
	if len(s.recs) > 0 {
		s.lastOp = s.recs[0].LastOP
	}
	s.hash = crypto.MD5File(s.path)
}

// Bytes returns the file content (GetSummaryAsMemStream).
func (s *SummaryDB) Bytes() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(s.path)
}

// Replace stores a downloaded summary (SaveSummaryToFile + SetSummaryHash)
// and rebuilds the index.
func (s *SummaryDB) Replace(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := writeFileAtomic(s.path, data)
	s.rebuildIndexLocked()
	return err
}

// Backup and Restore mirror CreateSumaryBackup / RestoreSumaryBackup.
func (s *SummaryDB) Backup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyFile(s.path, s.path+".bak")
}

// Restore copies the backup over the summary (the caller rebuilds the index).
func (s *SummaryDB) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyFile(s.path+".bak", s.path)
}
