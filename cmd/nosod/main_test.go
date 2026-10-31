package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/control"
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
