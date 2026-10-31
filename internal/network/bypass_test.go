package network

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func consensusGenesis() int64 { return int64(consensus.GenesysTimeStamp) }

// ReadLine keeps a partial line across a poll timeout (finding 7).
func TestReadLineKeepsPartialAcrossTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
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
	defer b.Close()
	c := NewConn(b)
	go func() { _, _ = a.Write([]byte("PSK 2 0.4")); a.Close() }()
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
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n') // the request
		_, _ = c.Write([]byte("SUMARYFILE\r\n"))
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
	e.request(sl, 6, "SUMARY")
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
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n')
		_, _ = r.ReadString('\n')
		fmt.Fprintf(c, "PSK 2 0.4.4zzz 1 $PONG 1 0 h %s 0 h 3 -1 m 0 null 0 g c p\r\n", fullHash)
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

// buildChain makes a node with three blocks and returns it.
func buildChain(t *testing.T, ck *clock) (*Engine, string) {
	n := mkNode(t, ck)
	base := int64(consensusGenesis()) + 600*10
	ck.v.Store(base)
	miner := n.Wallet.At(0).Hash
	for i := int64(1); i <= 3; i++ {
		ck.v.Add(600)
		if _, err := n.BuildNewBlock(i, ck.now(), n.MyLastBlockHash(), miner, BuildSolution); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	return e, miner
}

// Blocks must be the ones the headers name (finding 5).
func TestBlocksBoundToHeaders(t *testing.T) {
	var ck clock
	e, _ := buildChain(t, &ck)
	zipped, err := e.N.ZipBlocks(1)
	if err != nil {
		t.Fatal(err)
	}
	if !e.blocksMatchHeaders(zipped) {
		t.Fatal("the node's own blocks do not match its headers")
	}
	// block 1 with a different miner is a well-formed block, but not block 1
	raw, err := os.ReadFile(e.N.Lay.BlockFile(1))
	if err != nil {
		t.Fatal(err)
	}
	blk, err := storage.DecodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	blk.Header.AccountMiner = crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("1.blk")
	_, _ = w.Write(blk.Encode())
	_ = zw.Close()
	if e.blocksMatchHeaders(b.Bytes()) {
		t.Fatal("C-03: a block that differs from its header was accepted")
	}
	// a block beyond the headers has nothing to be checked against
	b.Reset()
	zw = zip.NewWriter(&b)
	w, _ = zw.Create("9.blk")
	_, _ = w.Write(raw)
	_ = zw.Close()
	if e.blocksMatchHeaders(b.Bytes()) {
		t.Fatal("C-03: a block without a header was accepted")
	}
}

// HEADUPDATE changes nothing unless the result has the voted hash (H-05).
func TestHeadUpdateVerifiedBeforeChange(t *testing.T) {
	var ck clock
	src, _ := buildChain(t, &ck)
	full, _ := src.N.Headers.Bytes()
	if len(full) < 4*types.ResumenSize {
		t.Fatalf("fixture has %d header records", len(full)/types.ResumenSize)
	}
	short := full[:3*types.ResumenSize] // records 0..2
	recs := func(r types.Resumen) string {
		return fmt.Sprintf("%d:%s:%s", r.Block, r.BlockHash, r.SumHash)
	}
	r3 := types.DecodeResumen(full[3*types.ResumenSize:])

	dst := NewEngine(mkNode(t, &ck))
	t.Cleanup(dst.Stop)
	// the destination holds blocks 0..2: copy them
	for i := int64(0); i <= 2; i++ {
		raw, _ := os.ReadFile(src.N.Lay.BlockFile(i))
		_ = os.WriteFile(dst.N.Lay.BlockFile(i), raw, 0o644)
	}
	dst.N.SetMyLastBlock(2)
	dst.N.Headers.Replace(short)
	dst.N.Headers.SetHash()
	dst.setConsensusForTest(CFullHeaders, crypto.IDHashBytes(full))

	junk := r3
	junk.BlockHash = strings.Repeat("A", 32)
	dst.headUpdate("PSK 2 0.4.4 1 HEADUPDATE $" + recs(junk))
	if got, _ := dst.N.Headers.Bytes(); !bytes.Equal(got, short) {
		t.Fatal("H-05: headers changed by a HEADUPDATE that does not produce the voted hash")
	}
	dst.headUpdate("PSK 2 0.4.4 1 HEADUPDATE $" + recs(r3))
	if got, _ := dst.N.Headers.Bytes(); !bytes.Equal(got, full) {
		t.Fatal("a correct HEADUPDATE was refused")
	}
}

// MNFILE and the other state files need the full hash (H-06).
func TestMNFileNeedsFullHash(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	text := "127.0.0.1;8080:" + crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0) + ":1:"
	line := "PSK 2 0.4.4 1 MNFILE $" + text
	full := crypto.IDHash(text + "\r\n")
	e.setConsensusForTest(CMNsHash, full[:5]) // the 20 bits an attacker can grind
	e.setConsensusForTest(CFullMNs, crypto.IDHash("another list\r\n"))
	e.processMNFile(line)
	if e.N.MNFile.Text() != "" && strings.Contains(e.N.MNFile.Text(), text) {
		t.Fatal("H-06: masternode file accepted on a 20-bit match")
	}
	e.setConsensusForTest(CFullMNs, full)
	e.processMNFile(line)
	if !strings.Contains(e.N.MNFile.Text(), text) {
		t.Fatal("the voted masternode file was refused")
	}
	if e.N.MNFile.Hash() != full {
		t.Fatalf("MNFile.Hash %s differs from the hash the receiver checks %s", e.N.MNFile.Hash(), full)
	}
}

// With no majority on a full hash, nothing is accepted.
func TestNoFullVoteNoFile(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	e.setConsensusForTest(CFullSummary, "")
	if e.fullHashOK(CFullSummary, "") || e.fullHashOK(CFullSummary, crypto.IDHash("x")) {
		t.Fatal("a file was accepted without a voted full hash")
	}
}

// The full hashes are voted like the other items, and only a majority of
// all configured seeds counts.
func TestFullHashesInConsensus(t *testing.T) {
	a, b, na, _, _ := connected(t)
	_, port, _ := splitHostPort(a.ServerAddr())
	b.SetNodesArray("127.0.0.1;" + port + ":")
	cons := b.CalculateConsensus()
	if cons[CFullSummary] != na.Summary.Hash() || cons[CFullHeaders] != na.Headers.Hash() ||
		cons[CFullGVTs] != na.GVTs.Hash() || cons[CFullPSO] != na.PSOs.FileHash() {
		t.Fatalf("full hashes missing from the consensus: %v", cons)
	}
	// two of three seeds silent: the single vote is no majority, so no
	// full hash is available even though the prefix items would be
	b.SetNodesArray("127.0.0.1;" + port + ":127.0.0.2;1:127.0.0.3;2:")
	if c := b.CalculateConsensus(); c[CFullSummary] != "" {
		t.Fatal("a full hash without a majority of the configured seeds")
	}
}

// A reply expected on one connection is not accepted on its successor in
// the same slot (finding 16).
func TestExpectationDiesWithConnection(t *testing.T) {
	a, b, _, _, _ := connected(t)
	b.expectReply(1, "SUMARY")
	b.CloseSlot(1)
	waitClosed(t, a, b)
	if sl := b.ReserveSlot(); sl != 1 {
		t.Fatalf("slot %d", sl)
	}
	if b.takeReply(1, "SUMARY") {
		t.Fatal("a new connection inherited the request of the old one")
	}
}

func TestLineAndByteBudgets(t *testing.T) {
	var ck clock
	ck.v.Store(1_700_000_000)
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	pre := "PSK 2 0.4.4 1 "
	if e.lineAllowed(1, pre+"$MNREPO "+strings.Repeat("x", 4<<20)) {
		t.Fatal("M-07: a 4 MiB $MNREPO line was accepted")
	}
	if e.lineAllowed(1, pre+"ORDER "+strings.Repeat("x", 70<<10)) {
		t.Fatal("M-07: an oversize ORDER line was accepted")
	}
	if !e.lineAllowed(2, pre+"MNFILE $"+strings.Repeat("x", 900<<10)) {
		t.Fatal("a real masternode file was refused")
	}
	n := 0
	for e.lineAllowed(3, pre+"$MNREPO a b c d e") {
		if n++; n > mnRepoBudget+5 {
			t.Fatal("M-07: no $MNREPO budget")
		}
	}
	if n != mnRepoBudget {
		t.Fatalf("budget %d", n)
	}
	// a new connection in the same slot starts clean
	e.SaveConnection("CLI", "9.9.9.9", nil, 3)
	e.CloseSlot(3)
	if !e.lineAllowed(3, pre+"$MNREPO a") {
		t.Fatal("budget survived the connection")
	}
	// byte budget
	for i := 0; i < 16; i++ {
		if !e.lineAllowed(4, pre+"MNFILE $"+strings.Repeat("x", 1000<<10)) {
			t.Fatalf("early refusal at %d", i)
		}
	}
	if e.lineAllowed(4, pre+"MNFILE $"+strings.Repeat("x", 1000<<10)) {
		t.Fatal("M-07: byte budget not enforced")
	}
	// queue by bytes
	e.SaveConnection("CLI", "8.8.8.8", nil, 5)
	big := strings.Repeat("x", 1<<20)
	ok := 0
	for e.addIncoming(5, big) {
		ok++
	}
	if ok != maxIncomingBytes/(1<<20) {
		t.Fatalf("queue held %d MiB", ok)
	}
}

// A peer that does not read cannot hold up the heartbeat while we send it
// a file (H-11, the send side).
func TestSlowReaderDoesNotBlockTick(t *testing.T) {
	var ck clock
	ck.v.Store(1_700_000_000)
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	a, b := net.Pipe() // unbuffered: a write blocks until the other end reads
	t.Cleanup(func() { a.Close(); b.Close() })
	sl := e.SaveConnection("CLI", "7.7.7.7", NewConn(a), -1)
	done := make(chan struct{})
	go func() {
		e.sendFile(sl, "SUMARYFILE", func() ([]byte, error) { return []byte("data"), nil })
		e.Tick()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("H-11: sending a file to a slow reader blocked the heartbeat")
	}
}

// Without a consensus nothing is "synced": empty hashes of empty slots must
// not match the empty consensus (the status bar showed 99 synced peers and
// the connection keeper stopped dialling).
func TestNoConsensusNoSyncedPeers(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	if n := e.SyncedConnections(); n != 0 {
		t.Fatalf("%d synced connections without a consensus", n)
	}
	if sl, ok := e.ValidSlotForSeed(); ok {
		t.Fatalf("slot %d chosen without a consensus", sl)
	}
}

// Two simultaneous connections from one IP cannot both be saved.
func TestSaveConnectionRefusesSecondSlotOfIP(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	t.Cleanup(e.Stop)
	if e.SaveConnection("CLI", "5.5.5.5", nil, -1) == 0 {
		t.Fatal("first refused")
	}
	if e.SaveConnection("CLI", "5.5.5.5", nil, -1) != 0 {
		t.Fatal("second connection of the same IP saved")
	}
}
