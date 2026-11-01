package node

import (
	"os"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/storage"
)

type storageOptions = storage.Options

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) {
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
