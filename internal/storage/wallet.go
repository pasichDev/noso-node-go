package storage

import (
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
}

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
	kp := crypto.GenerateKeyPair()
	var nw types.Wallet
	nw.Hash = crypto.GetAddressFromPublicKey(kp.PublicKey, 0)
	nw.PublicKey, nw.PrivateKey = kp.PublicKey, kp.PrivateKey
	w.Insert(nw)
	w.Save()
}

// Insert mirrors InsertToWallArr: duplicates (by hash or alias, only when
// the hash has at least 5 characters) are refused.
func (w *Wallet) Insert(d types.Wallet) bool {
	if w.IndexOf(d.Hash) >= 0 {
		return false
	}
	w.mu.Lock()
	w.arr = append(w.arr, d)
	w.mu.Unlock()
	return true
}

// IndexOf mirrors WallAddIndex: -1 for short strings or when absent.
func (w *Wallet) IndexOf(addr string) int {
	if addr == "" || len(addr) < 5 {
		return -1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
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

// Save mirrors SaveWalletToFile (nosowallcon.pas:278-306): the old file is
// copied to .bak before and after a successful write.
func (w *Wallet) Save() bool {
	_ = copyFile(w.path, w.path+".bak")
	w.mu.Lock()
	var out []byte
	for _, r := range w.arr {
		out = append(out, r.Encode()...)
	}
	w.mu.Unlock()
	if err := writeFileAtomic(w.path, out); err != nil {
		_ = copyFile(w.path+".bak", w.path)
		return false
	}
	_ = copyFile(w.path, w.path+".bak")
	return true
}

// Load mirrors LoadWallet; false when the file is missing or holds no
// complete record.
func (w *Wallet) Load() bool {
	raw, err := os.ReadFile(w.path)
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

// VerifyOnDisk mirrors VerifyAddressOnDisk.
func (w *Wallet) VerifyOnDisk(addr string) bool {
	raw, err := os.ReadFile(w.path)
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
	return os.WriteFile(path, d.Encode(), 0o644) == nil
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
