package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Regression tests for the re2 storage review (scratchpad/re2-storage.md).
// Each one failed on dbd506a.

func tRec() types.Wallet { return newWalletRecord(crypto.GenerateKeyPair()) }

func tPKW(rs ...types.Wallet) []byte {
	var o []byte
	for _, r := range rs {
		o = append(o, r.Encode()...)
	}
	return o
}

// tCount returns the number of records in a wallet file (sealed with pass or plain).
func tCount(t *testing.T, p string, pass []byte) int {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		return -1
	}
	if len(pass) > 0 {
		if raw, err = openWallet(raw, pass); err != nil {
			return -1
		}
	}
	return len(raw) / types.WalletSize
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permission test")
	}
}

// re2 #3: a torn wallet.pkw is an error, never an empty wallet, and the first
// save must not destroy wallet.pkw or its .bak.
func TestRE2TornPlainWalletFails(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	good := tPKW(tRec(), tRec(), tRec())
	torn := good[:300]
	os.WriteFile(p, torn, 0o600)
	if w, err := OpenWalletFor(p, nil, true, WalletOpenOptions{}); err == nil {
		t.Fatalf("torn wallet.pkw opened (Len=%d)", w.Len())
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, torn) {
		t.Fatal("a failed open changed wallet.pkw")
	}
}

// With a good .bak the torn file is replaced from it, and the torn file is kept.
func TestRE2TornPlainWalletRestoredFromBak(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	good := tPKW(tRec(), tRec(), tRec())
	os.WriteFile(p+".bak", good, 0o600)
	os.WriteFile(p, good[:300], 0o600)
	w, err := OpenWalletFor(p, nil, true, WalletOpenOptions{})
	if err != nil || w.Len() != 3 {
		t.Fatalf("restore from .bak: err=%v", err)
	}
	if _, err := w.NewAddress(); err != nil {
		t.Fatal(err)
	}
	if tCount(t, p, nil) != 4 || tCount(t, p+".bak", nil) != 4 {
		t.Fatal("records lost")
	}
	m, _ := filepath.Glob(filepath.Join(d, "wallet.pkw.damaged-*"))
	if len(m) != 1 {
		t.Fatalf("the damaged file was not kept: %v", m)
	}
}

func TestRE2UnreadablePlainWalletFails(t *testing.T) {
	skipIfRoot(t)
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	good := tPKW(tRec(), tRec())
	os.WriteFile(p+".bak", good, 0o600)
	os.WriteFile(p, good, 0o000)
	w, err := OpenWalletFor(p, nil, true, WalletOpenOptions{})
	if err == nil {
		t.Fatalf("unreadable wallet.pkw opened as Len=%d", w.Len())
	}
	if tCount(t, p+".bak", nil) != 2 {
		t.Fatal(".bak touched")
	}
}

// re2 #4: after wallet.enc is lost, a kept wallet.pkw must not win over the
// newer wallet.enc.bak, and the next save must not erase the backup's keys.
func TestRE2KeptPkwDoesNotOverrideNewerEncBak(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	pass := []byte("correct horse")
	os.WriteFile(p, tPKW(tRec()), 0o600)
	w, err := OpenWalletFor(p, pass, false, WalletOpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	na, err := w.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(d, "wallet.enc"))
	w2, err := OpenWalletFor(p, pass, false, WalletOpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w2.IndexOf(na.Hash) < 0 {
		t.Fatal("the newer key of wallet.enc.bak was not restored")
	}
	if _, err := w2.NewAddress(); err != nil {
		t.Fatal(err)
	}
	bak := &Wallet{path: filepath.Join(d, "wallet.enc.bak"), pass: pass}
	if !bak.Load() || bak.IndexOf(na.Hash) < 0 {
		t.Fatal("the backup lost the key")
	}
}

// re2 #4b: -insecure-plain-wallet next to a wallet.enc.bak must not start a new wallet.
func TestRE2InsecurePlainRefusesEncBak(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	s, _ := sealWallet(tPKW(tRec(), tRec()), []byte("pw"))
	os.WriteFile(filepath.Join(d, "wallet.enc.bak"), s, 0o600)
	if _, err := OpenWalletFor(p, nil, true, WalletOpenOptions{}); err == nil {
		t.Fatal("started a new plain wallet next to wallet.enc.bak")
	}
	if Exists(p) {
		t.Fatal("created wallet.pkw")
	}
}

// re2 #3: a backup is never overwritten by data that lacks its keys; it is kept under another name.
func TestRE2BackupNotOverwrittenBySmallerData(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	big := tPKW(tRec(), tRec(), tRec())
	os.WriteFile(p+".bak", big, 0o600)
	w := &Wallet{path: p}
	w.Insert(tRec())
	if err := w.SaveErr(); err != nil {
		t.Fatal(err)
	}
	found := false
	m, _ := filepath.Glob(p + ".bak*")
	for _, f := range m {
		if raw, _ := os.ReadFile(f); bytes.Equal(raw, big) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the 3 key backup is gone: %v", m)
	}
}

// re2 #12: createNew reports a failed save.
func TestRE2CreateNewReportsSaveFailure(t *testing.T) {
	skipIfRoot(t)
	d := t.TempDir()
	os.Chmod(d, 0o500)
	defer os.Chmod(d, 0o700)
	if w, err := OpenWalletFor(filepath.Join(d, "wallet.pkw"), nil, true, WalletOpenOptions{}); err == nil {
		t.Fatalf("handed out %s that is not on disk", w.At(0).Hash)
	}
}

// re2 #6: RetireLegacyWallet reads the .bak and reports shred failures.
func TestRE2RetireChecksBak(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	a, b := tRec(), tRec()
	_ = b
	os.WriteFile(p, tPKW(a), 0o600)
	os.WriteFile(p+".bak", tPKW(a, b), 0o600)
	pass := []byte("pw12345678")
	if _, err := OpenWalletFor(p, pass, false, WalletOpenOptions{}); err != nil {
		t.Fatal(err)
	}
	// a key that appeared in the .bak after the migration and is not in wallet.enc
	c := tRec()
	os.WriteFile(p+".bak", tPKW(a, c), 0o600)
	if err := RetireLegacyWallet(p, pass); err == nil || !Exists(p+".bak") {
		t.Fatalf("a .bak holding a key that wallet.enc lacks was shredded (err=%v)", err)
	}
}

func TestRE2RetireReportsShredFailure(t *testing.T) {
	skipIfRoot(t)
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	os.WriteFile(p, tPKW(tRec()), 0o600)
	pass := []byte("pw12345678")
	if _, err := OpenWalletFor(p, pass, false, WalletOpenOptions{}); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o400)
	os.Chmod(d, 0o500)
	defer os.Chmod(d, 0o700)
	if err := RetireLegacyWallet(p, pass); err == nil {
		t.Fatal("retire reported success but the clear-text wallet is still there")
	}
}

// re2 #8: permissions.
func TestRE2Permissions(t *testing.T) {
	skipIfRoot(t)
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	os.WriteFile(p, tPKW(tRec()), 0o644)
	os.Chmod(p, 0o644)
	os.WriteFile(p+".bak", tPKW(tRec()), 0o644)
	os.Chmod(p+".bak", 0o644)
	if _, err := OpenWalletFor(p, []byte("pw12345678"), false, WalletOpenOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, p + ".bak", filepath.Join(d, "wallet.enc"), filepath.Join(d, "wallet.enc.bak")} {
		if st, err := os.Stat(f); err == nil && st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %v", f, st.Mode())
		}
	}
	adv := filepath.Join(d, "advopt.txt")
	os.WriteFile(adv, nil, 0o644)
	os.Chmod(adv, 0o644)
	o := DefaultOptions("x")
	o.RPCSpendToken = "SECRET"
	if err := o.Save(adv); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(adv); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("advopt.txt mode %v", st.Mode())
	}
	root := filepath.Join(d, "N")
	NewLayout(root).EnsureDirs()
	if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode %v", st.Mode())
	}
}

// re2 #9: one bad line must not blank the security settings on the next save.
func TestRE2OptionsBadLineKeepsKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "advopt.txt")
	o := DefaultOptions("x")
	o.AdminKey, o.RPCSpendToken = "ADMIN", "TOK"
	o.Save(p)
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, append([]byte("HideEmpty maybe\n"), raw...), 0o600)
	q := DefaultOptions("x")
	if err := q.Load(p); err == nil {
		t.Fatal("bad line not reported")
	}
	q.Save(p)
	r := DefaultOptions("x")
	r.Load(p)
	if r.AdminKey != "ADMIN" || r.RPCSpendToken != "TOK" {
		t.Fatalf("keys blanked: %q %q", r.AdminKey, r.RPCSpendToken)
	}
}

// A line over the scanner limit leaves the rest unread: saving would blank it.
func TestRE2OptionsLongLineRefusesSave(t *testing.T) {
	p := filepath.Join(t.TempDir(), "advopt.txt")
	o := DefaultOptions("x")
	o.AdminKey = "ADMIN"
	o.Save(p)
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, append([]byte(strings.Repeat("A", 2<<20)+"\n"), raw...), 0o600)
	q := DefaultOptions("x")
	if err := q.Load(p); err == nil {
		t.Fatal("scanner error ignored")
	}
	if err := q.Save(p); err == nil {
		t.Fatal("saved over a file that was only partly read")
	}
	r := DefaultOptions("x")
	r.Load(p)
}

// re2 #10: a torn blocks_db tail must not shift later records.
func TestRE2BlocksDBTornTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db")
	x := OpenBlocksDB(p)
	x.Add(100, 1, 2, 3)
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte{0x65, 0, 0})
	f.Close()
	x.Add(102, 7, 8, 9)
	x.Add(103, 7, 8, 9)
	y := OpenBlocksDB(p)
	if y.LastBlock() != 103 || y.Records() != 3 || len(y.index[7]) != 2 {
		t.Fatalf("LastBlock=%d Records=%d index[7]=%v", y.LastBlock(), y.Records(), y.index[7])
	}
}

// re2 #7: copies are atomic and a missing source touches nothing.
func TestRE2CopyFileAtomic(t *testing.T) {
	d := t.TempDir()
	dst := filepath.Join(d, "b")
	os.WriteFile(dst, []byte("live"), 0o600)
	if err := copyFile(filepath.Join(d, "missing"), dst); err == nil {
		t.Fatal("missing source accepted")
	}
	if b, _ := os.ReadFile(dst); string(b) != "live" {
		t.Fatal("dst damaged")
	}
	g := OpenGVTs(filepath.Join(d, "g"))
	os.WriteFile(g.path, make([]byte, types.GVTSize*2), 0o600)
	g.Reload()
	if err := g.RestoreBackup(); err == nil || !Exists(g.path) || g.Len() != 2 {
		t.Fatalf("RestoreBackup without .bak: err=%v exists=%v Len=%d", err, Exists(g.path), g.Len())
	}
	os.WriteFile(g.path+".bak", []byte("old backup"), 0o600)
	os.Remove(g.path)
	if err := g.Backup(); err == nil {
		t.Fatal("backup of a missing file reported success")
	}
	if b, _ := os.ReadFile(g.path + ".bak"); string(b) != "old backup" {
		t.Fatal("a failed Backup removed the good .bak")
	}
}

// re2 #7: dropped write errors.
func TestRE2WriteErrorsReported(t *testing.T) {
	skipIfRoot(t)
	d := t.TempDir()
	g := OpenGVTs(filepath.Join(d, "gvts.psk"))
	ps := OpenPSOs(filepath.Join(d, "psos.dat"))
	os.Chmod(d, 0o500)
	defer os.Chmod(d, 0o700)
	if err := g.Save(); err == nil {
		t.Error("GVTs.Save dropped the error")
	}
	if err := ps.Save(5); err == nil {
		t.Error("PSOs.Save dropped the error")
	}
}

// re2 #14: a failed rename leaves no .tmp behind.
func TestRE2NoTmpLeftOnRenameFailure(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x")
	os.MkdirAll(filepath.Join(p, "sub"), 0o700) // rename onto a non-empty directory fails
	if err := writeFileAtomic(p, []byte("data")); err == nil {
		t.Fatal("expected failure")
	}
	if Exists(p + ".tmp") {
		t.Fatal(".tmp left behind")
	}
}

// re2 #11: import checks the key pair and refuses trailing bytes.
func TestRE2ImportChecksKeys(t *testing.T) {
	a, b := tRec(), tRec()
	a.PrivateKey = b.PrivateKey
	if _, err := ParsePKW(a.Encode()); err == nil {
		t.Error("foreign key imported")
	}
	if _, err := ParsePKW(append(tPKW(tRec()), 1, 2, 3)); err == nil {
		t.Error("trailing bytes accepted")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.pkw"), a.Encode(), 0o600)
	w := &Wallet{path: filepath.Join(t.TempDir(), "wallet.pkw")}
	if n := w.ImportFromBackup(dir); n != 0 {
		t.Errorf("ImportFromBackup took %d records with a foreign key", n)
	}
}
