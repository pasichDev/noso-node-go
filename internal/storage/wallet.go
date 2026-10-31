package storage

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

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
	// legacyKept names a wallet.pkw that was migrated and left in place.
	legacyKept string
}

// ErrWalletReadOnly is returned by Save/Add on a wallet opened read-only.
var ErrWalletReadOnly = errors.New("wallet: opened read-only")

// OpenWallet mirrors SetWalletFileName (nosowallcon.pas:60-70): a missing
// file creates a new wallet with one fresh address and ok=false.
func OpenWallet(path string) (w *Wallet, existed bool) {
	w = &Wallet{path: path}
	if !Exists(path) {
		w.createNew()
		return w, false
	}
	w.Load()
	return w, true
}

// Path returns the file path.
func (w *Wallet) Path() string { return w.path }

func (w *Wallet) createNew() {
	w.Insert(newWalletRecord(crypto.GenerateKeyPair()))
	w.Save()
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
	if len(w.pass) > 0 {
		var err error
		if out, err = sealWallet(out, w.pass); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(w.path, out); err != nil {
		return err // the previous file is untouched (rename never happened)
	}
	_ = writeFileAtomic(w.path+".bak", out)
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

// Load mirrors LoadWallet; false when the file is missing or holds no
// complete record.
func (w *Wallet) Load() bool {
	raw, err := w.readRecords()
	if err != nil {
		return false
	}
	n := len(raw) / types.WalletSize
	if n == 0 {
		return false
	}
	w.Clear()
	for i := 0; i < n; i++ {
		w.Insert(types.DecodeWallet(raw[i*types.WalletSize:]))
	}
	return true
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

// ParsePKW decodes a clear-text wallet file for import: every complete
// record, and an error when the file is not a plain wallet (for instance a
// wallet.enc, which is recognised and named as such).
func ParsePKW(raw []byte) ([]types.Wallet, error) {
	if len(raw) >= len(walletMagic) && string(raw[:len(walletMagic)]) == walletMagic {
		return nil, errors.New("wallet: this is an encrypted wallet.enc, not a .pkw; export with expwallet to get a .pkw")
	}
	if len(raw) < types.WalletSize {
		return nil, errors.New("wallet: file holds no complete record")
	}
	var out []types.Wallet
	for i := 0; i+types.WalletSize <= len(raw); i += types.WalletSize {
		out = append(out, types.DecodeWallet(raw[i:]))
	}
	return out, nil
}

// ReadAddressFile mirrors GetAddressFromFile: the first record of a file.
func ReadAddressFile(path string) (types.Wallet, bool) {
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

// ImportFromBackup mirrors ImportAddressesFromBackup: every *.pkw below dir
// is merged into the wallet; the count of added addresses is returned.
func (w *Wallet) ImportFromBackup(dir string) int {
	added := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".pkw" {
			if rec, ok := ReadAddressFile(p); ok && w.Insert(rec) {
				added++
			}
		}
		return nil
	})
	return added
}

func newWalletRecord(kp crypto.KeyPair) types.Wallet {
	var nw types.Wallet
	nw.Hash = crypto.GetAddressFromPublicKey(kp.PublicKey, 0)
	nw.PublicKey, nw.PrivateKey = kp.PublicKey, kp.PrivateKey
	return nw
}
