package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// re2 #5: a second holder of the data directory is refused; closing releases it.
func TestRE2LockDataDirExclusive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "NOSODATA")
	a, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDataDir(root); !errors.Is(err, ErrDataDirLocked) {
		t.Fatalf("second lock: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := LockDataDir(root)
	if err != nil {
		t.Fatalf("after Close: %v", err)
	}
	b.Close()
	if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode %v", st.Mode())
	}
}

func TestRE2TxnCommit(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "sub", "b")
	os.MkdirAll(filepath.Dir(b), 0o700)
	os.WriteFile(a, []byte("old a"), 0o600)
	tx := NewTxn(root)
	tx.Add(a, []byte("new a"))
	tx.Add(b, []byte("new b"))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{a: "new a", b: "new b"} {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("%s = %q", p, got)
		}
	}
	for _, p := range []string{a + ".new", b + ".new", filepath.Join(root, journalName)} {
		if Exists(p) {
			t.Errorf("%s left behind", p)
		}
	}
	if err := (&Txn{root: root, ops: []txnOp{{filepath.Join(root, "..", "x"), nil}}}).Commit(); err == nil {
		t.Error("path outside the root accepted")
	}
}

// Crash before the commit point: staged files are debris, the old state stays.
func TestRE2TxnCrashBeforeCommitRollsBack(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	os.WriteFile(a, []byte("old a"), 0o600)
	os.WriteFile(b, []byte("old b"), 0o600)
	os.WriteFile(a+".new", []byte("new a"), 0o600)
	os.WriteFile(b+".new", []byte("new b"), 0o600) // no manifest
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, p := range []string{a, b} {
		if got, _ := os.ReadFile(p); string(got) != "old "+filepath.Base(p) {
			t.Errorf("%s = %q", p, got)
		}
		if Exists(p + ".new") {
			t.Errorf("%s.new not swept", p)
		}
	}
}

// Crash after the commit point with only one file renamed: recovery completes it.
func TestRE2TxnCrashAfterCommitRollsForward(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	os.WriteFile(a, []byte("old a"), 0o600)
	os.WriteFile(b, []byte("old b"), 0o600)
	tx := NewTxn(root)
	tx.Add(a, []byte("new a"))
	tx.Add(b, []byte("new b"))
	// reproduce Commit up to the middle of the renames
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// put the state back as a crash would have left it: journal durable, a renamed, b still staged
	os.WriteFile(b, []byte("old b"), 0o600)
	os.WriteFile(b+".new", []byte("new b"), 0o600)
	var body []byte
	body = append(body, []byte(journalMagic+"\n")...)
	for _, p := range []struct{ n, d string }{{"a", "new a"}, {"b", "new b"}} {
		body = append(body, []byte(sumHex([]byte(p.d))+" "+p.n+"\n")...)
	}
	body = append(body, []byte("END "+sumHex(body)+"\n")...)
	os.WriteFile(filepath.Join(root, journalName), body, 0o600)
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for p, want := range map[string]string{a: "new a", b: "new b"} {
		if got, _ := os.ReadFile(p); string(got) != want {
			t.Errorf("%s = %q want %q", p, got, want)
		}
	}
	if Exists(filepath.Join(root, journalName)) || Exists(b+".new") {
		t.Error("journal or staged file left")
	}
}

// A torn or tampered manifest is not a commit.
func TestRE2TxnTornManifestIgnored(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	os.WriteFile(a, []byte("old"), 0o600)
	os.WriteFile(a+".new", []byte("new"), 0o600)
	os.WriteFile(filepath.Join(root, journalName), []byte(journalMagic+"\n"+sumHex([]byte("new"))+" a\nEN"), 0o600)
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got, _ := os.ReadFile(a); string(got) != "old" {
		t.Fatalf("a = %q", got)
	}
	if Exists(a+".new") || Exists(filepath.Join(root, journalName)) {
		t.Error("debris left")
	}
}

// A staged file that does not match the manifest is an error, never applied.
func TestRE2TxnMismatchRefused(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	os.WriteFile(a, []byte("old"), 0o600)
	os.WriteFile(a+".new", []byte("tampered"), 0o600)
	body := []byte(journalMagic + "\n" + sumHex([]byte("new")) + " a\n")
	body = append(body, []byte("END "+sumHex(body)+"\n")...)
	os.WriteFile(filepath.Join(root, journalName), body, 0o600)
	if _, err := LockDataDir(root); err == nil {
		t.Fatal("applied a staged file that does not match the journal")
	}
	if got, _ := os.ReadFile(a); string(got) != "old" {
		t.Fatalf("a = %q", got)
	}
}

// re2 #14: leftovers of interrupted atomic writes are removed at start.
func TestRE2LockSweepsTmp(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "BLOCKS"), 0o700)
	for _, n := range []string{"wallet.pkw.tmp", filepath.Join("BLOCKS", "5.blk.tmp")} {
		os.WriteFile(filepath.Join(root, n), []byte("x"), 0o600)
	}
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if Exists(filepath.Join(root, "wallet.pkw.tmp")) || Exists(filepath.Join(root, "BLOCKS", "5.blk.tmp")) {
		t.Error(".tmp not swept")
	}
}

func TestRE2WriteFileAtomicExportedKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	os.WriteFile(p, []byte("a"), 0o644)
	os.Chmod(p, 0o644)
	if err := WriteFileAtomic(p, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != "b" {
		t.Fatal(string(got))
	}
}

// re2 #13: the passphrase rule is shared; an existing wallet still opens.
func TestRE2CheckNewPassphrase(t *testing.T) {
	d := t.TempDir()
	if CheckNewPassphrase(d, []byte("short")) == nil {
		t.Error("short passphrase accepted for a new wallet")
	}
	if CheckNewPassphrase(d, []byte("long enough")) != nil {
		t.Error("long passphrase refused")
	}
	os.WriteFile(filepath.Join(d, "wallet.enc"), []byte("x"), 0o600)
	if CheckNewPassphrase(d, []byte("short")) != nil {
		t.Error("an existing wallet must open with its old short passphrase")
	}
}

// re2 #6 / M-5: the wallet knows its legacy files, warns, and retires them.
func TestRE2WalletRetireLegacyAPI(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "wallet.pkw")
	os.WriteFile(p, tPKW(tRec()), 0o600)
	os.WriteFile(p+".bak", tPKW(tRec()), 0o600)
	pass := []byte("pw12345678")
	w, err := OpenWalletFor(p, pass, false, WalletOpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w.LegacyWarning() == "" {
		t.Fatal("no warning while clear-text keys remain")
	}
	if err := w.RetireLegacy(); err != nil {
		t.Fatal(err)
	}
	if Exists(p) || Exists(p+".bak") || w.LegacyWarning() != "" {
		t.Error("legacy files or warning remain")
	}
	// the migration took both files' keys
	if w.Len() != 2 {
		t.Errorf("wallet.enc holds %d keys, want the 2 of wallet.pkw and its .bak", w.Len())
	}
	ro, err := OpenWalletFor(p, pass, false, WalletOpenOptions{ReadOnly: true})
	if err != nil || ro.RetireLegacy() == nil {
		t.Error("a read-only wallet retired files")
	}
}

func sumHex(b []byte) string {
	s := sha256sum(b)
	return s
}
