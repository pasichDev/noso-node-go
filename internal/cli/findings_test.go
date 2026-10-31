package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckNewPassphrase(t *testing.T) {
	dir := t.TempDir()
	if CheckNewPassphrase(dir, []byte("short")) == nil {
		t.Fatal("a 5 character passphrase may create a wallet")
	}
	if CheckNewPassphrase(dir, []byte("long enough")) != nil {
		t.Fatal("a long passphrase refused")
	}
	if err := os.WriteFile(filepath.Join(dir, "wallet.enc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if CheckNewPassphrase(dir, []byte("short")) != nil {
		t.Fatal("an existing wallet.enc must accept whatever opens it")
	}
}
