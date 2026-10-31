package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/types"
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

// expwallet writes records impwallet can read, never overwrites, and keeps
// the file private (findings 11, 2a).
func TestExpWalletRoundTripAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	n, err := node.New(filepath.Join(dir, "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	d := New(n, nil, nil)
	dest := filepath.Join(dir, "backup")
	out := strings.Join(d.Run("expwallet "+dest), "\n")
	if !strings.Contains(out, "backup.pkw") {
		t.Fatalf("export failed: %s", out)
	}
	raw, err := os.ReadFile(dest + ".pkw")
	if err != nil || len(raw) != n.Wallet.Len()*types.WalletSize {
		t.Fatalf("exported file has %d bytes for %d addresses (%v)", len(raw), n.Wallet.Len(), err)
	}
	if st, _ := os.Stat(dest + ".pkw"); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if types.DecodeWallet(raw).Hash != n.Wallet.At(0).Hash {
		t.Fatal("the export is not a plaintext wallet")
	}
	// a second export to the same name, and an export onto the live wallet
	before, _ := os.ReadFile(dest + ".pkw")
	out = strings.Join(d.Run("expwallet "+dest), "\n")
	if !strings.Contains(out, "Can not overwrite") {
		t.Fatalf("overwrite not refused: %s", out)
	}
	live := strings.TrimSuffix(n.Wallet.Path(), ".pkw")
	liveBefore, _ := os.ReadFile(n.Wallet.Path())
	d.Run("expwallet " + live)
	liveAfter, _ := os.ReadFile(n.Wallet.Path())
	if string(liveBefore) != string(liveAfter) {
		t.Fatal("expwallet touched the live wallet file")
	}
	if after, _ := os.ReadFile(dest + ".pkw"); string(after) != string(before) {
		t.Fatal("existing export overwritten")
	}
}
