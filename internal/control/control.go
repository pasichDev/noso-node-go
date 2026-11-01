// Package control is the local command channel between nosocli and nosod: a
// Unix domain socket inside the data directory (mode 0600) that accepts one
// console command line per connection and streams the output back.
package control

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// FIX(L6): the name includes the user, and the directory is checked (owner
	// and mode) by both ends, so another local user who creates it first is
	// noticed instead of trusted.
	return filepath.Join(os.TempDir(), fmt.Sprintf("nosod-%d-%s", os.Getuid(), hex.EncodeToString(sum[:8])), "s.sock")
}

// MaxLine bounds one command line.
const MaxLine = 64 << 10

// Runner executes a command and streams its output. proof is the wallet
// passphrase the client sent along (nil if none): commands that print or sign
// with private keys must check it, because the socket is open to every process
// of the same user and a passphrase typed into a GUI is held nowhere else.
// The result is false when the command failed.
type Runner func(line string, proof []byte, out func(string)) bool

// ErrFailed is returned by Call when the command ran but failed. Its output
// was written to the writer.
var ErrFailed = errors.New("command failed")

const (
	authPrefix = "\x01AUTH "
	failMarker = "\x00FAILED\n"
)

// Server is a running control socket.
type Server struct {
	ln   net.Listener
	path string
	wg   sync.WaitGroup
	mu   sync.Mutex
	idle map[net.Conn]struct{} // connections still waiting for their command line
}

// idleTimeout is how long a client may take to send its command line.
const idleTimeout = 30 * time.Second

// Serve listens on path until the server is closed.
func Serve(path string, run Runner) (*Server, error) {
	// FIX: the socket lives in a directory only the owner can enter, so the
	// moment between creating the socket and its chmod is not reachable by
	// other users.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// FIX(F-16): who owns the directory is checked before it is changed. A
	// chmod follows a link, so on a shared temporary directory another user
	// could have had any directory of ours set to 0700.
	if err := checkOwned(dir); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkOwner(dir); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	s := &Server{ln: ln, path: path, idle: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				// FIX(F-16): a client that sends nothing is dropped after
				// idleTimeout, and Close drops it at once; the command itself
				// then runs without a deadline of the connection.
				s.mu.Lock()
				s.idle[c] = struct{}{}
				s.mu.Unlock()
				_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
				// FIX: the command line is bounded (it was read without limit).
				r := bufio.NewReaderSize(io.LimitReader(c, MaxLine), 4<<10)
				line, err := r.ReadString('\n')
				var proof []byte
				if err == nil && strings.HasPrefix(line, authPrefix) { // optional first line: the wallet passphrase
					proof = []byte(strings.TrimRight(line[len(authPrefix):], "\r\n"))
					line, err = r.ReadString('\n')
				}
				s.mu.Lock()
				delete(s.idle, c)
				s.mu.Unlock()
				_ = c.SetReadDeadline(time.Time{})
				if err != nil && line == "" {
					return
				}
				if !run(strings.TrimRight(line, "\r\n"), proof, func(s string) { _, _ = io.WriteString(c, s+"\n") }) {
					_, _ = io.WriteString(c, failMarker)
				}
			}()
		}
	}()
	return s, nil
}

// Close stops accepting, waits for the commands in progress (FIX(M4): a
// restart used to reopen the data directory while an old command still wrote
// to it) and removes the socket.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.idle {
		_ = c.SetReadDeadline(time.Now()) // an idle client must not hold the close
	}
	s.mu.Unlock()
	s.wg.Wait()
	_ = os.Remove(s.path)
	return err
}

// Call sends one command to a running daemon and relays its output to w. It
// returns ErrFailed when the command ran and failed.
func Call(path, line string, w io.Writer) error { return CallAuth(path, line, nil, w) }

// CallAuth is Call with the wallet passphrase as proof for the commands that
// need it.
func CallAuth(path, line string, pass []byte, w io.Writer) error {
	if strings.HasPrefix(path, os.TempDir()) { // the shared-directory case
		if err := checkOwner(filepath.Dir(path)); err != nil {
			return err
		}
	}
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if len(pass) > 0 {
		if _, err := io.WriteString(c, authPrefix+string(pass)+"\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		return err
	}
	// stream the output, holding back the last bytes: they may be the marker
	var tail []byte
	chunk := make([]byte, 4096)
	for {
		n, err := c.Read(chunk)
		tail = append(tail, chunk[:n]...)
		if len(tail) > len(failMarker) {
			if _, werr := w.Write(tail[:len(tail)-len(failMarker)]); werr != nil {
				return werr
			}
			tail = append([]byte(nil), tail[len(tail)-len(failMarker):]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	failed := bytes.Equal(tail, []byte(failMarker))
	if !failed {
		if _, err := w.Write(tail); err != nil {
			return err
		}
	}
	if failed {
		return ErrFailed
	}
	return nil
}
