package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func encPath(l Layout) string { return filepath.Join(l.Root, "wallet.enc") }

func legacyWallet(t *testing.T, l Layout, n int) []byte {
	t.Helper()
	w, _ := OpenWallet(l.Wallet)
	for i := 1; i < n; i++ {
		w.Insert(newWalletRecord(crypto.GenerateKeyPair()))
	}
	w.Save()
	raw, err := os.ReadFile(l.Wallet)
	if err != nil || len(raw) != n*types.WalletSize {
		t.Fatalf("legacy wallet: %v %d", err, len(raw))
	}
	return raw
}

// A mistyped passphrase at migration must not cost the keys: wallet.pkw and
// its .bak stay byte-identical, and the right passphrase can still migrate
// after the bad wallet.enc is moved away.
func TestWalletMigrationKeepsOriginals(t *testing.T) {
	l := tmp(t)
	orig := legacyWallet(t, l, 3)
	bak, _ := os.ReadFile(l.Wallet + ".bak")
	w, err := OpenWalletEncrypted(l.Wallet, []byte("mistyped"))
	if err != nil || w.Len() != 3 {
		t.Fatalf("migrate: %v", err)
	}
	if w.LegacyKept() != l.Wallet {
		t.Fatal("front end is not told the plain copy remains")
	}
	for p, want := range map[string][]byte{l.Wallet: orig, l.Wallet + ".bak": bak} {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed or removed: %v", p, err)
		}
	}
	// the intended passphrase is refused, the message points at the originals
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("intended")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if got, _ := os.ReadFile(l.Wallet); !bytes.Equal(got, orig) {
		t.Fatal("a failed open touched wallet.pkw")
	}
	// recovery: move the bad wallet.enc away and migrate again
	_ = os.Rename(encPath(l), encPath(l)+".bad")
	w2, err := OpenWalletEncrypted(l.Wallet, []byte("intended"))
	if err != nil || w2.Len() != 3 {
		t.Fatalf("second migration: %v", err)
	}
}

// Migration seals every record, including ones the loader would drop
// (duplicates), byte for byte.
func TestWalletMigrationRoundTripExact(t *testing.T) {
	l := tmp(t)
	orig := legacyWallet(t, l, 2)
	dup := append(append([]byte(nil), orig...), orig[:types.WalletSize]...) // a duplicate record
	if err := os.WriteFile(l.Wallet, dup, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(encPath(l))
	back, err := openWallet(disk, []byte("pw"))
	if err != nil || !bytes.Equal(back, dup) {
		t.Fatalf("round trip differs: %v", err)
	}
}

func TestWalletMigrationRefusesBrokenKey(t *testing.T) {
	l := tmp(t)
	orig := legacyWallet(t, l, 1)
	a, b := types.DecodeWallet(orig), newWalletRecord(crypto.GenerateKeyPair())
	a.PrivateKey = b.PrivateKey // wrong private key for this public key
	if err := os.WriteFile(l.Wallet, a.Encode(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("pw")); err == nil {
		t.Fatal("inconsistent key migrated")
	}
	if got, _ := os.ReadFile(l.Wallet); !bytes.Equal(got, a.Encode()) {
		t.Fatal("original touched")
	}
	if Exists(encPath(l)) {
		t.Fatal("a half result was left behind")
	}
}

// A read-only open (status) neither migrates nor creates nor saves.
func TestWalletReadOnlyDoesNotMigrate(t *testing.T) {
	l := tmp(t)
	orig := legacyWallet(t, l, 2)
	w, err := OpenWalletEncryptedOpts(l.Wallet, []byte("pw"), WalletOpenOptions{ReadOnly: true})
	if err != nil || w.Len() != 2 {
		t.Fatalf("%v", err)
	}
	if Exists(encPath(l)) {
		t.Fatal("read-only open migrated")
	}
	if got, _ := os.ReadFile(l.Wallet); !bytes.Equal(got, orig) {
		t.Fatal("wallet.pkw changed")
	}
	if w.Save() {
		t.Fatal("read-only wallet saved")
	}
	if _, err := w.NewAddress(); err == nil {
		t.Fatal("read-only wallet handed out an address")
	}
	// empty data dir: nothing is created either
	l2 := tmp(t)
	if _, err := OpenWalletEncryptedOpts(l2.Wallet, []byte("pw"), WalletOpenOptions{ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if Exists(encPath(l2)) || Exists(l2.Wallet) {
		t.Fatal("read-only open created a wallet")
	}
}

// -insecure-plain-wallet wins over a passphrase, never migrates, and refuses
// to start a second wallet next to a wallet.enc.
func TestInsecurePlainWalletSemantics(t *testing.T) {
	l := tmp(t)
	orig := legacyWallet(t, l, 2)
	w, err := OpenWalletFor(l.Wallet, []byte("pw"), true, WalletOpenOptions{})
	if err != nil || w.Len() != 2 || w.Path() != l.Wallet {
		t.Fatalf("%v", err)
	}
	if Exists(encPath(l)) {
		t.Fatal("plain mode migrated")
	}
	if got, _ := os.ReadFile(l.Wallet); !bytes.Equal(got, orig) {
		t.Fatal("plain wallet changed")
	}
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWalletFor(l.Wallet, nil, true, WalletOpenOptions{}); err == nil {
		t.Fatal("plain mode accepted next to wallet.enc")
	}
}

// A vanished wallet.enc must not make a new wallet that overwrites .bak.
func TestWalletMissingEncRestoresFromBak(t *testing.T) {
	l := tmp(t)
	w, err := OpenWalletEncrypted(l.Wallet, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	addr := w.At(0).Hash
	if err := os.Remove(encPath(l)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("wrong")); err == nil {
		t.Fatal("created a new wallet over the backup")
	}
	if !Exists(encPath(l) + ".bak") {
		t.Fatal("backup gone")
	}
	w2, err := OpenWalletEncrypted(l.Wallet, []byte("pw"))
	if err != nil || w2.At(0).Hash != addr {
		t.Fatalf("restore: %v", err)
	}
}

func TestRetireLegacyWalletIsExplicitAndChecked(t *testing.T) {
	l := tmp(t)
	legacyWallet(t, l, 2)
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := RetireLegacyWallet(l.Wallet, []byte("other")); err == nil || !Exists(l.Wallet) {
		t.Fatal("retired with the wrong passphrase")
	}
	if err := RetireLegacyWallet(l.Wallet, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if Exists(l.Wallet) || Exists(l.Wallet+".bak") {
		t.Fatal("not removed")
	}
}

// PoC: parallel getnewaddress calls lost keys on disk.
func TestWalletConcurrentAddKeepsEveryKey(t *testing.T) {
	for round := 0; round < 3; round++ {
		l := tmp(t)
		w, err := OpenWalletEncrypted(l.Wallet, []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		var handed []string
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				nw, err := w.NewAddress()
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				handed = append(handed, nw.Hash)
				mu.Unlock()
			}()
		}
		wg.Wait()
		c := &Wallet{path: w.path, pass: w.pass}
		if !c.Load() || c.Len() != 7 {
			t.Fatalf("round %d: disk holds %d of 7", round, c.Len())
		}
		for _, h := range handed {
			if !c.VerifyOnDisk(h) {
				t.Fatalf("handed out %s is not on disk", h)
			}
		}
	}
}

// The unsynchronised Insert+Save pair of the old callers must also converge:
// the last Save on disk holds everything in memory.
func TestWalletConcurrentInsertSaveConverges(t *testing.T) {
	for round := 0; round < 3; round++ {
		l := tmp(t)
		w, _ := OpenWalletEncrypted(l.Wallet, []byte("pw"))
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.Insert(newWalletRecord(crypto.GenerateKeyPair()))
				w.Save()
			}()
		}
		wg.Wait()
		c := &Wallet{path: w.path, pass: w.pass}
		if !c.Load() || c.Len() != w.Len() {
			t.Fatalf("round %d: disk %d memory %d", round, c.Len(), w.Len())
		}
	}
}

func TestWalletVerifyOnDiskEncrypted(t *testing.T) {
	l := tmp(t)
	w, _ := OpenWalletEncrypted(l.Wallet, []byte("pw"))
	if !w.VerifyOnDisk(w.At(0).Hash) {
		t.Fatal("own address not found on disk")
	}
	if w.VerifyOnDisk("NnotInTheWallet0000000000000000") {
		t.Fatal("foreign address found")
	}
}

// expwallet: a true .pkw that ImportFromBackup/ParsePKW accept and that holds
// the same keys.
func TestWalletExportPKWRoundTrip(t *testing.T) {
	l := tmp(t)
	w, _ := OpenWalletEncrypted(l.Wallet, []byte("pw"))
	if _, err := w.NewAddress(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.pkw")
	if err := w.ExportPKW(dest); err != nil {
		t.Fatal(err)
	}
	if err := w.ExportPKW(dest); err == nil {
		t.Fatal("overwrote an existing export")
	}
	if st, _ := os.Stat(dest); st.Mode().Perm() != 0o600 || st.Size() != 2*types.WalletSize {
		t.Fatalf("mode/size %v %d", st.Mode(), st.Size())
	}
	raw, _ := os.ReadFile(dest)
	recs, err := ParsePKW(raw)
	if err != nil || len(recs) != 2 || recs[1].PrivateKey != w.At(1).PrivateKey {
		t.Fatalf("parse: %v", err)
	}
	fresh, _ := OpenWallet(filepath.Join(t.TempDir(), "wallet.pkw"))
	if n := fresh.ImportFromBackup(dir); n != 1 {
		t.Fatalf("import added %d (ImportFromBackup reads the first record of each file)", n)
	}
	enc, _ := os.ReadFile(encPath(l))
	if _, err := ParsePKW(enc); err == nil {
		t.Fatal("wallet.enc accepted as .pkw")
	}
}

func FuzzParsePKW(f *testing.F) {
	f.Add(make([]byte, types.WalletSize))
	f.Add([]byte("NOSOWLT1"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		recs, err := ParsePKW(b)
		if err == nil && len(recs) != len(b)/types.WalletSize {
			t.Fatalf("%d records from %d bytes", len(recs), len(b))
		}
		_ = verifyKeys(b)
	})
}
