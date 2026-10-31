package network

import (
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
	if l, err := cb.ReadLine(time.Second); err != nil || l != "last-no-eol" {
		t.Fatalf("%q %v", l, err)
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
