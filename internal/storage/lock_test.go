package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A second holder of the data directory is refused; closing releases it.
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
	if st, _ := os.Stat(root); runtime.GOOS != "windows" && st.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode %v", st.Mode())
	}
}

// F-13: a planted commit.journal is only a file. It is not read, applied or
// allowed to stop the start, and nothing outside the root is touched.
func TestPlantedTxnManifestIsIgnored(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := "NOSOTXN1\n" + sumHexForTest("x") + " ../" + filepath.Base(outside) + "\nEND 00\n"
	if err := os.WriteFile(filepath.Join(root, "commit.journal"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatalf("a planted manifest stopped the start: %v", err)
	}
	l.Close()
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatal("a file outside the data directory was replaced")
	}
}

// F-14: links in the data directory are never followed.
func TestLinksInTheDataDirectoryAreNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	root := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	// .lock as a link: refused, the target is not truncated
	if err := os.Symlink(victim, filepath.Join(root, ".lock")); err != nil {
		t.Fatal(err)
	}
	if l, err := LockDataDir(root); err == nil {
		l.Close()
		t.Fatal("a .lock link was accepted")
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("the target of the .lock link was changed: %q", b)
	}
	_ = os.Remove(filepath.Join(root, ".lock"))
	// a wallet temporary that is a link: the link goes, the target stays
	if err := os.Symlink(victim, filepath.Join(root, "wallet-x.tmp")); err != nil {
		t.Fatal(err)
	}
	l, err := LockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("the target of the temporary link was zeroed: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(root, "wallet-x.tmp")); err == nil {
		t.Fatal("the link was left behind")
	}
}

func sumHexForTest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
