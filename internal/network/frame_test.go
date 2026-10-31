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
	if d, err := cb.ReadStream(time.Second); err != nil || string(d) != "hello-bytes" {
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
