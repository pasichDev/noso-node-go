//go:build !windows

package control

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// F-16: a client that connects and sends nothing does not hold Close.
func TestCloseDoesNotWaitForAnIdleClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	s, err := Serve(path, func(string, []byte, func(string)) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()   // test cleanup
	time.Sleep(100 * time.Millisecond) // let the server take the connection
	done := make(chan struct{})
	go func() { _ = s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close is held by a client that sent nothing")
	}
}

// F-16: a socket directory that is a link is refused before anything is
// changed through it.
func TestServeRefusesALinkedSocketDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if s, err := Serve(filepath.Join(link, "s.sock"), func(string, []byte, func(string)) bool { return true }); err == nil {
		_ = s.Close()
		t.Fatal("a socket directory that is a link was accepted")
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
		t.Fatalf("the target of the link was chmodded to %v", st.Mode().Perm())
	}
}
