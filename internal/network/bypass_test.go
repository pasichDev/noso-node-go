package network

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// ReadLine keeps a partial line across a poll timeout (finding 7).
func TestReadLineKeepsPartialAcrossTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }() // test cleanup
	defer func() { _ = b.Close() }() // test cleanup
	c := NewConn(b)
	go func() {
		_, _ = a.Write([]byte("PSK 2 0.4.4 123 $PI"))
		time.Sleep(300 * time.Millisecond)
		_, _ = a.Write([]byte("NG 1 2 3\r\n"))
	}()
	var l string
	var err error
	for i := 0; i < 20; i++ {
		l, err = c.ReadLine(100 * time.Millisecond)
		if err == nil {
			break
		}
	}
	if l != "PSK 2 0.4.4 123 $PING 1 2 3" {
		t.Fatalf("line corrupted: got %q (%v)", l, err)
	}
}

// A line cut by EOF is an error, not a complete line (finding 7, Indy raises).
func TestReadLineTruncatedAtEOF(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }() // test cleanup
	c := NewConn(b)
	go func() { _, _ = a.Write([]byte("PSK 2 0.4")); _ = a.Close() }()
	if l, err := c.ReadLine(time.Second); err == nil {
		t.Fatalf("truncated line returned as complete: %q", l)
	}
}

// One peer that stalls a requested transfer must not stop the heartbeat
// (H-11 bypass, finding 4).
func TestStalledTransferDoesNotBlockTick(t *testing.T) {
	var ck clock
	ck.v.Store(1700000000)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n') // the request
		_, _ = c.Write([]byte("BLOCKZIP\r\n"))
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], 1000)
		_, _ = c.Write(h[:]) // then silence
		time.Sleep(10 * time.Second)
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	sl := e.ConnectClient("127.0.0.1", p)
	if sl == 0 {
		t.Fatal("connect")
	}
	e.expectReply(sl, "BLOCKS")
	e.PTCSendLine(sl, e.ProtocolLine(8))
	time.Sleep(500 * time.Millisecond)
	done := make(chan struct{})
	go func() { e.Tick(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Tick blocked by a stalled transfer")
	}
	e.CloseSlot(sl)
}

// serveSummary runs a fake peer: it advertises fullHash in its PONG and
// answers the summary request with data.
func serveSummary(t *testing.T, fullHash string, data []byte) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test cleanup
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = fmt.Fprintf(c, "PSK 2 0.4.4zzz 1 $PONG 1 0 h %s 0 h 3 -1 m 0 null 0 g c p\r\n", fullHash)
		time.Sleep(600 * time.Millisecond)
		_, _ = r.ReadString('\n')
		var b bytes.Buffer
		b.WriteString("SUMARYFILE\r\n")
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(data)))
		b.Write(h[:])
		b.Write(data)
		_, _ = c.Write(b.Bytes())
		time.Sleep(3 * time.Second)
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

// C-03 bypass: the forged summary carries the 5-character consensus value
// (what a 20-bit grind produces) and the peer's own PING names its full
// hash. It must not be stored because the seeds' full-hash vote differs.
func TestForgedSummaryWithMatchingPrefixRefused(t *testing.T) {
	var ck clock
	ck.v.Store(1700000000 - 1700000000%600 + 100)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	attacker := crypto.GenerateKeyPair()
	addr := crypto.GetAddressFromPublicKey(attacker.PublicKey, 0)
	raw, _ := n.Summary.Bytes()
	rec := types.Summary{Hash: addr, Balance: 2000000000000000, LastOP: 1}
	forged := append(append([]byte(nil), raw...), rec.Encode()...)
	full := crypto.IDHashBytes(forged)
	honest := crypto.IDHashBytes([]byte("honest network summary"))
	e.setConsensusForTest(CSumHash, full[:5])   // the ground 20 bits agree
	e.setConsensusForTest(CFullSummary, honest) // the seeds vote for the honest full hash
	sl := e.ConnectClient("127.0.0.1", serveSummary(t, full, forged))
	if sl == 0 {
		t.Fatal("connect")
	}
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 5; i++ {
		e.Tick()
		time.Sleep(50 * time.Millisecond)
	}
	e.request(sl, 6, "SUMARY")
	for i := 0; i < 40; i++ {
		e.Tick()
		time.Sleep(50 * time.Millisecond)
	}
	if got := n.Summary.BalanceIndexed(addr); got != 0 {
		t.Fatalf("forged summary stored, attacker balance %d", got)
	}
}
