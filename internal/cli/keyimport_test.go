package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-17: the private key comes from a file or from stdin, never from argv.
func TestNewFromKeysTakesTheKeyFromAFileOrStdin(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(f, []byte("PRIVATEKEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := PrepareKeyImport("newfromkeys PUB "+f, nil)
	if err != nil || got != "newfromkeys PUB PRIVATEKEY" {
		t.Fatalf("file: %q %v", got, err)
	}
	got, err = PrepareKeyImport("newfromkeys PUB -", strings.NewReader(" PRIVATEKEY \n"))
	if err != nil || got != "newfromkeys PUB PRIVATEKEY" {
		t.Fatalf("stdin: %q %v", got, err)
	}
	// the key typed on the command line is refused
	for _, bad := range []string{"newfromkeys PUB PRIVATEKEYASWORD", "newfromkeys PUB", "newfromkeys PUB a b", "newfromkeys PUB -"} {
		if _, err := PrepareKeyImport(bad, nil); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if out, _ := PrepareKeyImport("balance", nil); out != "balance" {
		t.Fatal("another command was changed")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := PrepareKeyImport("newfromkeys PUB "+empty, nil); err == nil {
		t.Fatal("an empty key file was accepted")
	}
}
