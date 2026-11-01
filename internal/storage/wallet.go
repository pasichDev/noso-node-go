package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Wallet is wallet.pkw: a flat file of 626-byte WalletData records
// (nosowallcon.pas).
type Wallet struct {
	mu   sync.Mutex
	path string
	arr  []types.Wallet
	// pass, when set, encrypts the file (FIX(H-10)); path then names the
	// encrypted file.
	pass []byte
	// readOnly refuses Save: set by the read-only open modes so a status
	// style command can never write the wallet.
	readOnly bool
	// openErr is set on the placeholder OpenWallet returns when the file
	// could not be opened safely; every write is refused with it.
	openErr error
	// plainPath is the legacy wallet.pkw next to an encrypted wallet.
	plainPath string
	// legacyKept names a wallet.pkw that is still on disk next to wallet.enc.
	legacyKept string
	warnings   []string
}

// ErrWalletReadOnly is returned by Save/Add on a wallet opened read-only.
var ErrWalletReadOnly = errors.New("wallet: opened read-only")

// ErrWalletDamaged is returned when a wallet file exists but cannot be read
// completely (torn write, short file). Nothing is overwritten.
var ErrWalletDamaged = errors.New("wallet: file is damaged (not a whole number of records)")

// OpenWallet mirrors SetWalletFileName (nosowallcon.pas:60-70): a missing
// file creates a new wallet with one fresh address and existed=false.
//
// FIX(re2 #3): it no longer turns an unreadable or torn file into an empty
// wallet. In that case the returned wallet is a read-only placeholder that
// refuses every write; use OpenWalletPlain to get the error.
func OpenWallet(path string) (w *Wallet, existed bool) {
	existed = Exists(path)
	w, err := OpenWalletPlain(path)
	if err != nil {
		return &Wallet{path: path, readOnly: true, openErr: err}, existed
	}
	return w, existed
}

// OpenWalletPlain opens the clear-text wallet.pkw. A missing file (and no
// .bak) creates a new wallet with one fresh address, and a failure to write it
// is an error. A file that cannot be read, or holds a torn record, is an error
// and nothing is written; a torn file next to a complete .bak is replaced
// from the .bak and kept as wallet.pkw.damaged-<time>. Keys found in the .bak
// but not in wallet.pkw are added.
func OpenWalletPlain(path string) (*Wallet, error) { return openWalletPlain(path, false) }

func openWalletPlain(path string, readOnly bool) (*Wallet, error) {
	w := &Wallet{path: path, readOnly: readOnly}
	raw, err := os.ReadFile(path)
	bak, _ := readWholeRecords(path + ".bak")
	switch {
	case err == nil:
		recs, whole := splitRecords(raw)
		if !whole || len(recs) == 0 {
			if len(bak) == 0 {
				return nil, fmt.Errorf("%w: %s (%d bytes); the file was not changed", ErrWalletDamaged, path, len(raw))
			}
			w.warn("wallet.pkw is damaged; restored from wallet.pkw.bak")
			if !readOnly {
				if err := preserveDamaged(path); err != nil {
					return nil, err
				}
			}
		}
		w.arr = nil
		for _, r := range recs {
			w.Insert(r)
		}
		if n := w.mergeRecords(bak); n > 0 {
			w.warn(fmt.Sprintf("%d key(s) found only in wallet.pkw.bak were added", n))
		}
		if !readOnly && (!whole || len(w.arr) > len(recs)) {
			if err := w.SaveErr(); err != nil {
				return nil, err
			}
		}
	case errors.Is(err, fs.ErrNotExist):
		if len(bak) > 0 {
			w.mergeRecords(bak)
			w.warn("wallet.pkw is missing; restored from wallet.pkw.bak")
			if !readOnly {
				if err := w.SaveErr(); err != nil {
					return nil, err
				}
			}
		} else if Exists(path + ".bak") {
			return nil, fmt.Errorf("%w: %s.bak exists but holds no complete record; not starting a new wallet over it", ErrWalletDamaged, path)
		} else if !readOnly {
			if err := w.createNew(); err != nil {
				return nil, err
			}
		}
	default:
		return nil, err // unreadable: not proven damaged, never replaced
	}
	if !readOnly {
		tightenFiles(path, path+".bak")
	}
	return w, nil
}

// readWholeRecords reads a clear-text wallet-style file; ok records only when
// the file is a whole number of records.
func readWholeRecords(path string) ([]types.Wallet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	recs, whole := splitRecords(raw)
	if !whole {
		return nil, ErrWalletDamaged
	}
	return recs, nil
}

func splitRecords(raw []byte) (recs []types.Wallet, whole bool) {
	n := len(raw) / types.WalletSize
	for i := 0; i < n; i++ {
		recs = append(recs, types.DecodeWallet(raw[i*types.WalletSize:]))
	}
	return recs, len(raw)%types.WalletSize == 0
}

// preserveDamaged moves a damaged file aside; it is never deleted.
func preserveDamaged(path string) error {
	return os.Rename(path, fmt.Sprintf("%s.damaged-%d", path, time.Now().UnixNano()))
}

// mergeRecords adds every record whose address the wallet does not hold yet
// and returns how many were added.
func (w *Wallet) mergeRecords(rs []types.Wallet) int {
	n := 0
	for _, r := range rs {
		if w.Insert(r) {
			n++
		}
	}
	return n
}

func (w *Wallet) warn(s string) { w.warnings = append(w.warnings, s) }

// Warnings lists what the open or the saves did that the user should know:
// restored from a backup, a backup kept under another name, a failed backup
// write. Front ends print them.
func (w *Wallet) Warnings() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.warnings...)
}

// tightenFiles sets mode 0600 on wallet files that exist (no-op on Windows,
// see Layout.EnsureDirs).
func tightenFiles(paths ...string) {
	for _, p := range paths {
		if Exists(p) {
			_ = os.Chmod(p, 0o600)
		}
	}
}

// Path returns the file path.
func (w *Wallet) Path() string { return w.path }

func (w *Wallet) createNew() error {
	w.Insert(newWalletRecord(crypto.GenerateKeyPair()))
	if err := w.SaveErr(); err != nil { // FIX(re2 #12): no address that is not on disk
		w.Clear()
		return err
	}
	return nil
}

// Insert mirrors InsertToWallArr: duplicates (by hash or alias, only when
// the hash has at least 5 characters) are refused.
func (w *Wallet) Insert(d types.Wallet) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.indexLocked(d.Hash) >= 0 {
		return false
	}
	w.arr = append(w.arr, d)
	return true
}

// IndexOf mirrors WallAddIndex: -1 for short strings or when absent.
func (w *Wallet) IndexOf(addr string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.indexLocked(addr)
}

func (w *Wallet) indexLocked(addr string) int {
	if addr == "" || len(addr) < 5 {
		return -1
	}
	for i, r := range w.arr {
		if r.Hash == addr || r.Custom == addr {
			return i
		}
	}
	return -1
}

// At mirrors GetWallArrIndex: zero record when out of range.
func (w *Wallet) At(i int) types.Wallet {
	w.mu.Lock()
	defer w.mu.Unlock()
	if i >= 0 && i <= len(w.arr)-1 {
		return w.arr[i]
	}
	return types.Wallet{}
}

// Set replaces the record at i (used by balance refreshes).
func (w *Wallet) Set(i int, d types.Wallet) {
	w.mu.Lock()
	if i >= 0 && i < len(w.arr) {
		w.arr[i] = d
	}
	w.mu.Unlock()
}

// Len mirrors LenWallArr.
func (w *Wallet) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.arr)
}

// All returns a copy of every record.
func (w *Wallet) All() []types.Wallet {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]types.Wallet(nil), w.arr...)
}

// Clear mirrors ClearWalletArray.
func (w *Wallet) Clear() {
	w.mu.Lock()
	w.arr = nil
	w.mu.Unlock()
}

// Swap mirrors ChangeWallArrPos.
func (w *Wallet) Swap(a, b int) bool {
	n := w.Len()
	if a > n-1 || b > n-1 || a == b || a < 0 || b < 0 {
		return false
	}
	w.mu.Lock()
	w.arr[a], w.arr[b] = w.arr[b], w.arr[a]
	w.mu.Unlock()
	return true
}

// ClearPendings mirrors ClearWallPendings.
func (w *Wallet) ClearPendings() {
	w.mu.Lock()
	for i := range w.arr {
		w.arr[i].Pending = 0
	}
	w.mu.Unlock()
}

// SetPending mirrors SetPendingForAddress.
func (w *Wallet) SetPending(i int, v int64) {
	w.mu.Lock()
	if i >= 0 && i < len(w.arr) {
		w.arr[i].Pending = v
	}
	w.mu.Unlock()
}

// Save mirrors SaveWalletToFile (nosowallcon.pas:278-306): the wallet is
// written atomically and then copied to .bak. Saves are serialised per file
// (CS_WalletFile in the original) and every Save writes the wallet as it is
// when the lock is taken, so a slow older Save can no longer land last.
// Callers that hand out a new address must use Add/NewAddress, which check
// the result; Save only reports it.
func (w *Wallet) Save() bool { return w.SaveErr() == nil }

// SaveErr is Save with the reason of a failure.
func (w *Wallet) SaveErr() error {
	if w.openErr != nil {
		return w.openErr
	}
	if w.readOnly {
		return ErrWalletReadOnly
	}
	lk := lockFor(w.path)
	lk.Lock()
	defer lk.Unlock()
	return w.saveLocked()
}

func (w *Wallet) saveLocked() error {
	w.mu.Lock()
	var out []byte
	for _, r := range w.arr {
		out = append(out, r.Encode()...)
	}
	w.mu.Unlock()
	data := out
	if len(w.pass) > 0 {
		var err error
		if data, err = sealWallet(out, w.pass); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(w.path, data); err != nil {
		return err // the previous file is untouched (rename never happened)
	}
	// The backup is only ever replaced by data that contains its keys; an
	// older or unreadable backup is kept under another name (re2 #3).
	if err := w.protectBackup(out); err != nil {
		w.warn("wallet backup: " + err.Error())
		return nil
	}
	if err := writeFileAtomic(w.path+".bak", data); err != nil {
		w.warn("wallet backup not written: " + err.Error())
	}
	return nil
}

// keysOf decodes the records of a wallet file (decrypting when w is encrypted).
func (w *Wallet) keysOf(raw []byte) ([]types.Wallet, bool) {
	if len(w.pass) > 0 {
		var err error
		if raw, err = openWallet(raw, w.pass); err != nil {
			return nil, false
		}
	}
	recs, whole := splitRecords(raw)
	return recs, whole
}

// protectBackup moves the existing .bak aside unless it can be proven that
// every key in it is in plain (the records about to be written).
func (w *Wallet) protectBackup(plain []byte) error {
	bakPath := w.path + ".bak"
	raw, err := os.ReadFile(bakPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		if old, ok := w.keysOf(raw); ok {
			have := map[string]string{}
			now, _ := splitRecords(plain)
			for _, r := range now {
				have[r.Hash] = r.PrivateKey
			}
			covered := true
			for _, r := range old {
				if k, ok := have[r.Hash]; !ok || k != r.PrivateKey {
					covered = false
					break
				}
			}
			if covered {
				return nil
			}
		}
	}
	keep := fmt.Sprintf("%s.%d.old", bakPath, time.Now().UnixNano())
	if err := os.Rename(bakPath, keep); err != nil {
		return err
	}
	w.warn("the previous backup holds keys this wallet does not; it was kept as " + filepath.Base(keep))
	return nil
}

// Add inserts d and writes the wallet through before returning. added is
// false for a duplicate. If the write fails the record is removed again and
// the error returned, so an address is never handed out that is not on disk.
func (w *Wallet) Add(d types.Wallet) (added bool, err error) {
	if w.readOnly {
		return false, ErrWalletReadOnly
	}
	lk := lockFor(w.path)
	lk.Lock()
	defer lk.Unlock()
	if !w.Insert(d) {
		return false, nil
	}
	if err := w.saveLocked(); err != nil {
		w.removeHash(d.Hash)
		return false, err
	}
	return true, nil
}

// NewAddress generates a key pair, adds it and writes the wallet through.
func (w *Wallet) NewAddress() (types.Wallet, error) {
	nw := newWalletRecord(crypto.GenerateKeyPair())
	if _, err := w.Add(nw); err != nil {
		return types.Wallet{}, err
	}
	return nw, nil
}

func (w *Wallet) removeHash(h string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, r := range w.arr {
		if r.Hash == h {
			w.arr = append(w.arr[:i], w.arr[i+1:]...)
			return
		}
	}
}

// readRecords returns the plain record bytes of the file on disk
// (decrypting wallet.enc when a passphrase is set).
func (w *Wallet) readRecords() ([]byte, error) {
	raw, err := os.ReadFile(w.path)
	if err != nil {
		return nil, err
	}
	if len(w.pass) > 0 {
		return openWallet(raw, w.pass)
	}
	return raw, nil
}

// Load mirrors LoadWallet; false when the file is missing, cannot be
// decrypted or read completely, or holds no complete record.
func (w *Wallet) Load() bool { return w.LoadErr() == nil }

// LoadErr is Load with the reason of a failure. A file that is not a whole
// number of records is ErrWalletDamaged and the wallet is left as it was.
func (w *Wallet) LoadErr() error {
	raw, err := w.readRecords()
	if err != nil {
		return err
	}
	recs, whole := splitRecords(raw)
	if !whole {
		return ErrWalletDamaged
	}
	if len(recs) == 0 {
		return errors.New("wallet: file holds no complete record")
	}
	w.Clear()
	for _, r := range recs {
		w.Insert(r)
	}
	return nil
}

// VerifyOnDisk mirrors VerifyAddressOnDisk. The file is decrypted when the
// wallet is encrypted (the original compared plain records).
func (w *Wallet) VerifyOnDisk(addr string) bool {
	raw, err := w.readRecords()
	if err != nil {
		return false
	}
	for i := 0; i < len(raw)/types.WalletSize; i++ {
		if types.DecodeWallet(raw[i*types.WalletSize:]).Hash == addr {
			return true
		}
	}
	return false
}

// ExportPKW writes the wallet to dest as a true wallet.pkw: clear-text
// 626-byte records, exactly what ExpWallet of the original produces and what
// ImportWallet/ImportFromBackup accept. It is a clear-text copy of every
// private key: the caller must warn the user (PKWExportWarning) and the file
// is created 0600. An existing dest is never overwritten.
func (w *Wallet) ExportPKW(dest string) error {
	if Exists(dest) {
		return os.ErrExist
	}
	var out []byte
	for _, r := range w.All() {
		out = append(out, r.Encode()...)
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(out)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(dest) // our own partial file, not the user's
	}
	return werr
}

// PKWExportWarning is the text to show after ExportPKW.
const PKWExportWarning = "WARNING: the exported file holds your private keys in clear text. Keep it offline and delete it after use."

// MaxImportSize caps a wallet file accepted for import.
const MaxImportSize = 4 << 20

// ParsePKW decodes a clear-text wallet file for import: every record, and an
// error when the file is not a plain wallet (for instance a wallet.enc, which
// is recognised and named as such), is not a whole number of records, is
// larger than MaxImportSize, or holds a record whose private key does not
// match its public key or whose address does not derive from it (re2 #11).
func ParsePKW(raw []byte) ([]types.Wallet, error) {
	if len(raw) >= len(walletMagic) && string(raw[:len(walletMagic)]) == walletMagic {
		return nil, errors.New("wallet: this is an encrypted wallet.enc, not a .pkw; export with expwallet to get a .pkw")
	}
	if len(raw) < types.WalletSize {
		return nil, errors.New("wallet: file holds no complete record")
	}
	if len(raw) > MaxImportSize {
		return nil, errors.New("wallet: file too large to import")
	}
	if len(raw)%types.WalletSize != 0 {
		return nil, fmt.Errorf("%w: %d bytes", ErrWalletDamaged, len(raw))
	}
	if err := verifyKeys(raw); err != nil {
		return nil, err
	}
	recs, _ := splitRecords(raw)
	return recs, nil
}

// ReadAddressFile mirrors GetAddressFromFile: the first record of a file.
func ReadAddressFile(path string) (types.Wallet, bool) {
	if st, err := os.Stat(path); err != nil || st.Size() > MaxImportSize {
		return types.Wallet{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < types.WalletSize {
		return types.Wallet{}, false
	}
	return types.DecodeWallet(raw), true
}

// SaveAddressFile mirrors SaveAddresstoFile.
func SaveAddressFile(path string, d types.Wallet) bool {
	return os.WriteFile(path, d.Encode(), 0o600) == nil
}

// ImportFromBackup mirrors ImportAddressesFromBackup: the first record of
// every *.pkw below dir whose key pair checks out is merged into the wallet
// and, if anything was added, written through. The count of added addresses
// is returned.
func (w *Wallet) ImportFromBackup(dir string) int {
	added := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".pkw" {
			if rec, ok := ReadAddressFile(p); ok && verifyKeys(rec.Encode()) == nil && w.Insert(rec) {
				added++
			}
		}
		return nil
	})
	if added > 0 && !w.readOnly {
		if err := w.SaveErr(); err != nil {
			w.warn("imported addresses were not saved: " + err.Error())
		}
	}
	return added
}

func newWalletRecord(kp crypto.KeyPair) types.Wallet {
	var nw types.Wallet
	nw.Hash = crypto.GetAddressFromPublicKey(kp.PublicKey, 0)
	nw.PublicKey, nw.PrivateKey = kp.PublicKey, kp.PrivateKey
	return nw
}
