// Package control is the local command channel between nosocli and nosod: a
// Unix domain socket inside the data directory (mode 0600) that accepts one
// console command line per connection and streams the output back.
package control

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SocketPath returns the socket path for a data directory.
//
// Unix socket paths are limited to about 100 bytes; longer data directories
// use a short name in the temporary directory derived from the directory.
func SocketPath(dataDir string) string {
	p := filepath.Join(dataDir, "nosod.sock")
	if len(p) <= 100 {
		return p
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(os.TempDir(), "nosod-"+hex.EncodeToString(sum[:4])+".sock")
}

// Runner executes a command and streams its output.
type Runner func(line string, out func(string))

// Serve listens on path until the listener is closed.
func Serve(path string, run Runner) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Minute))
				r := bufio.NewReaderSize(c, 64<<10)
				line, err := r.ReadString('\n')
				if err != nil && line == "" {
					return
				}
				run(strings.TrimRight(line, "\r\n"), func(s string) { _, _ = io.WriteString(c, s+"\n") })
			}()
		}
	}()
	return ln, nil
}

// Call sends one command to a running daemon and relays its output to w.
func Call(path, line string, w io.Writer) error {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		return err
	}
	_, err = io.Copy(w, c)
	return err
}
