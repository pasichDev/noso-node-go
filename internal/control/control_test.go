package control

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func serve(t *testing.T, run Runner) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	s, err := Serve(path, run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return path
}

// A command that fails is reported to the caller as ErrFailed, with its
// output; a command that succeeds is not.
func TestCallReportsFailure(t *testing.T) {
	path := serve(t, func(line string, _ []byte, out func(string)) bool {
		out("answer to " + line)
		return !strings.HasPrefix(line, "bad")
	})
	var ok, bad bytes.Buffer
	if err := Call(path, "good one", &ok); err != nil || ok.String() != "answer to good one\n" {
		t.Fatalf("good: %v %q", err, ok.String())
	}
	if err := Call(path, "bad one", &bad); !errors.Is(err, ErrFailed) || bad.String() != "answer to bad one\n" {
		t.Fatalf("bad: %v %q", err, bad.String())
	}
}

// The passphrase travels as proof only when the client sends it, and is never
// part of the command line the daemon runs.
func TestCallAuthDeliversTheProof(t *testing.T) {
	var mu sync.Mutex
	var gotLine string
	var gotProof []byte
	path := serve(t, func(line string, proof []byte, out func(string)) bool {
		mu.Lock()
		gotLine, gotProof = line, proof
		mu.Unlock()
		return true
	})
	got := func() (string, []byte) { mu.Lock(); defer mu.Unlock(); return gotLine, gotProof }
	var w bytes.Buffer
	if err := CallAuth(path, "showkeys N1", []byte("correct horse"), &w); err != nil {
		t.Fatal(err)
	}
	if l, p := got(); l != "showkeys N1" || string(p) != "correct horse" {
		t.Fatalf("line %q proof %q", l, p)
	}
	if err := Call(path, "balance", &w); err != nil {
		t.Fatal(err)
	}
	if l, p := got(); l != "balance" || p != nil {
		t.Fatalf("without proof: line %q proof %q", l, p)
	}
}
