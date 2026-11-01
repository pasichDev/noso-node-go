package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// `restart` really restarts: the daemon closes the node and opens the data
// directory again in the same process, and `quit` ends it (finding 12).
func TestRestartReopensInProcess(t *testing.T) {
	t.Setenv("NOSO_WALLET_PASSPHRASE", "correct horse battery")
	dir := filepath.Join(t.TempDir(), "NOSODATA")
	opt := options{data: dir, noP2P: true, noNTP: true}
	sig := make(chan os.Signal, 1)
	sock := control.SocketPath(dir)

	ask := func(line string) string {
		var out bytes.Buffer
		for i := 0; i < 100; i++ {
			out.Reset()
			if err := control.Call(sock, line, &out); err == nil {
				return out.String()
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("control socket never answered %q", line)
		return ""
	}
	results := make(chan bool, 3)
	go func() {
		for {
			r := run(opt, sig)
			results <- r
			if !r {
				return
			}
		}
	}()
	ask("restart")
	select {
	case r := <-results:
		if !r {
			t.Fatal("restart ended the daemon")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("restart did not return")
	}
	// the second run must be serving again on the same data directory
	if got := ask("balance"); !strings.Contains(got, "NOSO") {
		t.Fatalf("restarted daemon does not answer: %q", got)
	}
	sig <- os.Interrupt
	select {
	case r := <-results:
		if r {
			t.Fatal("a signal asked for a restart")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestPrestartDue(t *testing.T) {
	for _, c := range []struct {
		at, now, age int64
		want         bool
	}{
		{0, 1000, 200, false},   // not set
		{1000, 999, 200, false}, // too early
		{1000, 1001, 100, false},
		{1000, 1001, 200, true},
		{1000, 1001, 449, true},
		{1000, 1001, 450, false}, // the block is about to close
	} {
		if got := prestartDue(c.at, c.now, c.age); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

// PRestart N restarts the node N block periods after it started. The chain
// clock of this test runs 100 times faster, so a period is six seconds.
func TestPRestartOptionRestartsTheDaemon(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a block period of chain time")
	}
	t.Setenv("NOSO_WALLET_PASSPHRASE", "correct horse battery")
	dir := filepath.Join(t.TempDir(), "NOSODATA")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := os.WriteFile(filepath.Join(dir, "devnet.txt"),
		[]byte(fmt.Sprintf("anchor %d\nbase %d\nscale 100\n", now, now)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "advopt.txt"), []byte("PRestart 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	go func() { done <- run(options{data: dir, noP2P: true, noNTP: true}, sig) }()
	select {
	case restart := <-done:
		if !restart {
			t.Fatal("the daemon stopped instead of restarting")
		}
	case <-time.After(60 * time.Second):
		sig <- os.Interrupt
		t.Fatal("PRestart 1 never restarted the daemon")
	}
}

// F-6: another process of the same user cannot take a private key out of the
// running node through its control socket without the passphrase.
func TestControlSocketKeepsKeysBehindThePassphrase(t *testing.T) {
	const pass = "correct horse battery"
	t.Setenv("NOSO_WALLET_PASSPHRASE", pass)
	dir := filepath.Join(t.TempDir(), "NOSODATA")
	sig := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	go func() { done <- run(options{data: dir, noP2P: true, noNTP: true}, sig) }()
	sock := control.SocketPath(dir)
	var addr string
	for i := 0; i < 200 && addr == ""; i++ {
		var out bytes.Buffer
		if control.Call(sock, "pubkey", &out) == nil {
			addr = strings.Fields(out.String())[0]
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if addr == "" {
		t.Fatal("no control socket")
	}
	var out bytes.Buffer
	err := control.Call(sock, "showkeys "+addr, &out)
	if !errors.Is(err, control.ErrFailed) || !strings.Contains(out.String(), "passphrase") {
		t.Fatalf("showkeys without proof: %v %q", err, out.String())
	}
	out.Reset()
	if err := control.CallAuth(sock, "showkeys "+addr, []byte(pass), &out); err != nil || len(strings.Fields(out.String())) < 2 {
		t.Fatalf("showkeys with the passphrase: %v %q", err, out.String())
	}
	sig <- os.Interrupt
	<-done
}

// F-15: a restart keeps the data directory lock. A run that is handed the lock
// does not take it again (it would fail: the directory is locked), and it
// releases it when it ends without a restart.
func TestRunUsesTheLockItIsHandedAndReleasesIt(t *testing.T) {
	t.Setenv("NOSO_WALLET_PASSPHRASE", "correct horse battery")
	dir := filepath.Join(t.TempDir(), "NOSODATA")
	l, err := storage.LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	carriedLock = l
	sig := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	go func() { done <- run(options{data: dir, noP2P: true, noNTP: true}, sig) }()
	time.Sleep(500 * time.Millisecond)
	if _, err := storage.LockDataDir(dir); err == nil {
		t.Fatal("the directory was not locked while the node ran")
	}
	sig <- os.Interrupt
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	l2, err := storage.LockDataDir(dir)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	_ = l2.Close() // test cleanup
}
