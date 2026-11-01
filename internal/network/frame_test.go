package network

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestFraming(t *testing.T) {
	a, b := net.Pipe()
	ca, cb := NewConn(a), NewConn(b)
	go func() {
		_ = ca.WriteLine("PSK 2 0.4.4Ab9 1700000000 $PING 3")
		_ = ca.WriteStream("RESUMENFILE", []byte("hello-bytes"))
		_, _ = a.Write([]byte("bare-lf\nlast-no-eol"))
		a.Close()
	}()
	if l, err := cb.ReadLine(time.Second); err != nil || l != "PSK 2 0.4.4Ab9 1700000000 $PING 3" {
		t.Fatalf("%q %v", l, err)
	}
	if l, _ := cb.ReadLine(time.Second); l != "RESUMENFILE" {
		t.Fatal(l)
	}
	if d, err := cb.ReadStream(time.Second, 1<<20); err != nil || string(d) != "hello-bytes" {
		t.Fatalf("%q %v", d, err)
	}
	if l, _ := cb.ReadLine(time.Second); l != "bare-lf" {
		t.Fatal("LF only line must be accepted")
	}
	// a line cut off by the end of the connection is an error (Indy raises)
	if l, err := cb.ReadLine(time.Second); err == nil {
		t.Fatalf("truncated line accepted: %q", l)
	}
}

func TestWireBytes(t *testing.T) {
	a, b := net.Pipe()
	ca := NewConn(a)
	done := make(chan []byte)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		done <- buf[:n]
	}()
	_ = ca.WriteStream("GVTSFILE", []byte{1, 2, 3})
	got := <-done
	want := "GVTSFILE\r\n\x00\x00\x00\x03\x01\x02\x03"
	if string(got) != want {
		t.Fatalf("%q != %q", got, want)
	}
}

func FuzzReadLine(f *testing.F) {
	f.Add([]byte("abc\r\ndef\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, b := net.Pipe()
		go func() { _, _ = a.Write(data); a.Close() }()
		c := NewConn(b)
		for i := 0; i < 8; i++ {
			if _, err := c.ReadLine(50 * time.Millisecond); err != nil {
				return
			}
		}
	})
}

// FIX(H-11): a declared size above the per-kind maximum is refused before
// any allocation, and a stalled sender hits the deadline.
func TestStreamLimits(t *testing.T) {
	a, b := net.Pipe()
	cb := NewConn(b)
	go func() { _, _ = a.Write([]byte{0x7f, 0xff, 0xff, 0xff}) }()
	if _, err := cb.ReadStream(time.Second, 1<<20); err != ErrTooLong {
		t.Fatalf("oversize accepted: %v", err)
	}
	a2, b2 := net.Pipe()
	c2 := NewConn(b2)
	go func() { _, _ = a2.Write([]byte{0, 0, 0, 10, 1, 2}) }() // promises 10 bytes, sends 2
	start := time.Now()
	if _, err := c2.ReadStream(300*time.Millisecond, 1<<20); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("stalled transfer not cut: %v", err)
	}
	a3, b3 := net.Pipe()
	go func() { _, _ = a3.Write([]byte{0xff, 0xff, 0xff, 0xff}) }() // negative length
	if _, err := NewConn(b3).ReadStream(time.Second, 1<<20); err != ErrTooLong {
		t.Fatal("negative length accepted")
	}
}

// F-19: a receiver that takes nothing frees the send slot after the stall
// limit instead of holding it for the whole transfer; one that reads is served.
func TestWriteStreamGivesUpOnAReaderThatTakesNothing(t *testing.T) {
	oldStall, oldTotal := streamStall, streamTotal
	streamStall, streamTotal = 100*time.Millisecond, 2*time.Second
	defer func() { streamStall, streamTotal = oldStall, oldTotal }()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { done <- NewConn(a).WriteStream("FILE", make([]byte, 1<<20)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a transfer to a peer that reads nothing succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the slot is still held by a peer that reads nothing")
	}

	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	go func() { _, _ = io.Copy(io.Discard, d) }()
	if err := NewConn(c).WriteStream("FILE", make([]byte, 1<<20)); err != nil {
		t.Fatalf("a reading peer was cut off: %v", err)
	}
}
