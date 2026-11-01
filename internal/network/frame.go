// Package network implements the Noso peer-to-peer protocol: line framing,
// the server and client roles, the PING/PONG state exchange, file
// transfers, consensus polling and the synchronisation state machine.
package network

import (
	"bufio"
	"bytes"
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
	// pend holds the start of a line whose end has not arrived yet.
	pend []byte
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

// Limits of a file transfer. FIX(F-19): the write used to have one deadline for
// the whole file, so a peer that read nothing (or a trickle) held one of the
// few send slots for its full length, and eight such peers held all of them.
// Now every chunk must be taken within streamStall, the transfer as a whole
// within streamTotal, and after streamGrace the peer must keep up with
// streamMinRate bytes per second on average. They are variables so tests can
// shorten them.
var (
	streamChunk   = 32 << 10
	streamStall   = 10 * time.Second
	streamTotal   = 120 * time.Second
	streamGrace   = 5 * time.Second
	streamMinRate = int64(16 << 10)
)

// errSlowReader ends a transfer whose receiver does not keep up.
var errSlowReader = errors.New("peer reads too slowly")

// WriteStream sends label as a line and then the file framing, as one
// serialised unit.
func (c *Conn) WriteStream(label string, data []byte) error {
	c.wm <- struct{}{}
	defer func() { <-c.wm }()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	start := time.Now()
	var written int64
	put := func(p []byte) error {
		for len(p) > 0 {
			chunk := p
			if len(chunk) > streamChunk {
				chunk = chunk[:streamChunk]
			}
			el := time.Since(start)
			if el > streamTotal {
				return errSlowReader
			}
			_ = c.c.SetWriteDeadline(time.Now().Add(streamStall))
			n, err := c.c.Write(chunk)
			written += int64(n)
			if err != nil {
				return err
			}
			p = p[len(chunk):]
			if el = time.Since(start); el > streamGrace && written < int64(el.Seconds())*streamMinRate {
				return errSlowReader
			}
		}
		return nil
	}
	if err := put(append([]byte(label+"\r\n"), hdr[:]...)); err != nil {
		return err
	}
	return put(data)
}

// ReadLine reads one line with the given timeout (0 = no deadline). Bytes
// read before a timeout stay in c.pend and are completed by the next call
// (Indy keeps them in its InputBuffer); a line cut off by the end of the
// connection is an error, not a short line.
func (c *Conn) ReadLine(timeout time.Duration) (string, error) {
	if timeout > 0 {
		_ = c.c.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = c.c.SetReadDeadline(time.Time{})
	}
	for {
		frag, err := c.r.ReadSlice('\n')
		c.pend = append(c.pend, frag...)
		if len(c.pend) > MaxLine {
			c.pend = nil
			return "", ErrTooLong
		}
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(c.pend) > 0 {
			c.pend = nil
			return "", io.ErrUnexpectedEOF
		}
		return "", err
	}
	s := strings.TrimSuffix(string(c.pend), "\n")
	c.pend = c.pend[:0]
	return strings.TrimSuffix(s, "\r"), nil
}

// Buffered reports whether unread bytes are already queued locally
// (IOHandler.InputBufferIsEmpty is false).
func (c *Conn) Buffered() bool { return c.r.Buffered() > 0 }

// StreamIdle is how long a transfer may stay silent between two reads.
const StreamIdle = 10 * time.Second

// ReadStream reads the Int32 length and body that follow a file label line.
// FIX(H-11): the caller gives the maximum size for the kind of file, the
// buffer grows with the data actually received (the original presized the
// stream from the unauthenticated length, IdIOHandler.ReadStream), one
// deadline covers the whole transfer and a peer that goes quiet for
// StreamIdle loses it.
func (c *Conn) ReadStream(total time.Duration, max int) ([]byte, error) {
	end := time.Now().Add(total)
	setDeadline := func() {
		d := time.Now().Add(StreamIdle)
		if d.After(end) {
			d = end
		}
		_ = c.c.SetReadDeadline(d)
	}
	setDeadline()
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int32(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || int64(n) > int64(max) || int64(n) > MaxStream {
		return nil, ErrTooLong
	}
	var buf bytes.Buffer
	chunk := make([]byte, 32<<10)
	for left := int64(n); left > 0; {
		want := int64(len(chunk))
		if left < want {
			want = left
		}
		setDeadline()
		m, err := c.r.Read(chunk[:want])
		buf.Write(chunk[:m])
		left -= int64(m)
		if err != nil && left > 0 {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
