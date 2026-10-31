// Package network implements the Noso peer-to-peer protocol: line framing,
// the server and client roles, the PING/PONG state exchange, file
// transfers, consensus polling and the synchronisation state machine.
package network

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// MaxLine bounds one received text line (hardening: Indy's MaxLineLength is
// set to MaxInt in the original, so honest peers never get close).
const MaxLine = 4 << 20

// MaxStream bounds one received file (hardening: the largest real file is
// the summary, a few megabytes).
const MaxStream = 256 << 20

// ErrTooLong is returned for oversize lines or streams.
var ErrTooLong = errors.New("network: line or stream too long")

// Conn wraps a socket with Indy-compatible framing: lines are written as
// text + CR LF and read up to LF with a preceding CR stripped
// (IdIOHandler.pas WriteLn/ReadLn with the default LF terminator); files
// are an Int32 big-endian length followed by that many bytes
// (TIdIOHandler.Write(stream,0,true) / ReadStream).
type Conn struct {
	c  net.Conn
	r  *bufio.Reader
	wm chan struct{}
}

// NewConn wraps c.
func NewConn(c net.Conn) *Conn {
	return &Conn{c: c, r: bufio.NewReaderSize(c, 64<<10), wm: make(chan struct{}, 1)}
}

// Raw returns the socket.
func (c *Conn) Raw() net.Conn { return c.c }

// Close closes the socket.
func (c *Conn) Close() error { return c.c.Close() }

// RemoteIP returns the peer IP without the port.
func (c *Conn) RemoteIP() string {
	h, _, err := net.SplitHostPort(c.c.RemoteAddr().String())
	if err != nil {
		return c.c.RemoteAddr().String()
	}
	return h
}

// WriteLine sends one line (CR LF terminated).
func (c *Conn) WriteLine(s string) error {
	c.wm <- struct{}{}
	defer func() { <-c.wm }()
	_ = c.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := io.WriteString(c.c, s+"\r\n")
	return err
}

// WriteStream sends label as a line and then the file framing, as one
// serialised unit.
func (c *Conn) WriteStream(label string, data []byte) error {
	c.wm <- struct{}{}
	defer func() { <-c.wm }()
	_ = c.c.SetWriteDeadline(time.Now().Add(120 * time.Second))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	buf := append([]byte(label+"\r\n"), hdr[:]...)
	buf = append(buf, data...)
	_, err := c.c.Write(buf)
	return err
}

// ReadLine reads one line with the given timeout (0 = no deadline).
func (c *Conn) ReadLine(timeout time.Duration) (string, error) {
	if timeout > 0 {
		_ = c.c.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = c.c.SetReadDeadline(time.Time{})
	}
	var sb strings.Builder
	for {
		frag, err := c.r.ReadSlice('\n')
		sb.Write(frag)
		if sb.Len() > MaxLine {
			return "", ErrTooLong
		}
		if err == nil {
			break
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF && sb.Len() > 0 {
				break
			}
			return "", err
		}
	}
	s := strings.TrimSuffix(sb.String(), "\n")
	return strings.TrimSuffix(s, "\r"), nil
}

// Buffered reports whether unread bytes are already queued locally
// (IOHandler.InputBufferIsEmpty is false).
func (c *Conn) Buffered() bool { return c.r.Buffered() > 0 }

// ReadStream reads the Int32 length and body that follow a file label line.
func (c *Conn) ReadStream(timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		_ = c.c.SetReadDeadline(time.Now().Add(timeout))
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int32(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || int64(n) > MaxStream {
		return nil, ErrTooLong
	}
	buf := make([]byte, n)
	for read := 0; read < int(n); {
		if timeout > 0 {
			_ = c.c.SetReadDeadline(time.Now().Add(timeout))
		}
		m, err := c.r.Read(buf[read:])
		read += m
		if err != nil && read < int(n) {
			return nil, err
		}
	}
	return buf, nil
}
