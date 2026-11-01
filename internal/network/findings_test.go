package network

import (
	"archive/zip"
	"bytes"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// reporter makes a node that would report itself as a masternode at ip with
// its own first wallet address (unfunded unless the caller funds it).
func reporter(t *testing.T, ck *clock, ip string) (*Engine, string) {
	n := mkNode(t, ck)
	n.UpdateOptions(func(o *node.StorageOptions) {
		o.MNIP, o.MNPort = ip, "8080"
		o.MNFunds, o.MNSign = n.Wallet.At(0).Hash, n.Wallet.At(0).Hash
	})
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	return e, e.ProtocolLine(13)
}

// H-3: a garbage or unstaked report is dropped before it can burn the IP slot
// of a real masternode or cost a dial.
func TestH3_ReportCheckedBeforeIPSlotAndDial(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, &ck)
	n.SetMyLastBlock(150000) // past block 110000 a masternode needs the full stake
	e := NewEngine(n)
	var dials atomic.Int32
	e.Dial = func(string, time.Duration) (net.Conn, error) { dials.Add(1); return nil, errors.New("no") }
	garbage := "PSK 2 0.4.4 1 $MNREPO 8.8.4.4 garbage"
	e.queueMNReport(garbage)
	if n.WaitingMNsLen() != 0 || n.MNIPReceived(garbage) {
		t.Fatal("H-3: garbage was queued or marked the IP as received")
	}
	// well formed and signed, but the key holds no stake
	r, _ := reporter(t, &ck, "8.8.8.8")
	r.N.SetMyLastBlock(150000)
	rep := r.ProtocolLine(13)
	e.queueMNReport(rep)
	if n.WaitingMNsLen() != 0 || n.MNIPReceived(rep) {
		t.Fatal("H-3: a report without stake was queued")
	}
	if dials.Load() != 0 {
		t.Fatal("H-3: dialled for an unstaked report")
	}
}

// M-1: only the node's own full identity skips the challenge.
func TestM1_OwnIPAloneIsChallenged(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	e, own := reporter(t, &ck, "8.8.4.4")
	var dials atomic.Int32
	e.Dial = func(string, time.Duration) (net.Conn, error) { dials.Add(1); return nil, errors.New("no") }
	if !e.challengeReport(own) || dials.Load() != 0 {
		t.Fatal("the node's own report must pass without a dial")
	}
	_, stranger := reporter(t, &ck, "8.8.4.4") // same IP, other keys
	if e.challengeReport(stranger) || dials.Load() == 0 {
		t.Fatal("M-1: a report naming our IP with other keys skipped the challenge")
	}
}

// H5: answers made of many lines are not cut off by the general line budget.
func TestH5_BulkLinesHaveTheirOwnBudget(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	e := NewEngine(mkNode(t, &ck))
	for i := 0; i < 1000; i++ {
		if !e.lineBudget(3, "PSK 2 v 1 $MNREPO 1.2.3.4 x") {
			t.Fatalf("H5: report line %d refused", i)
		}
		if !e.lineBudget(4, "PSK 2 v 1 ORDER 1 $x") {
			t.Fatalf("H5: order line %d refused", i)
		}
	}
	ok := 0
	for i := 0; i < 500; i++ {
		if e.lineBudget(5, "PSK 2 v 1 $PING 1") {
			ok++
		}
	}
	if ok != 200 {
		t.Fatalf("general budget allowed %d lines, want 200", ok)
	}
}

// Re2 consensus 8: an archive carries as many blocks as fit the byte budget,
// consecutive from the first.
func TestBlockArchiveIsBounded(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	big := make([]byte, 12<<20)
	for i := 1; i <= 6; i++ {
		if err := os.WriteFile(n.Lay.BlockFile(int64(i)), big, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n.SetMyLastBlock(6)
	z, err := e.zipBlocksFrom(1)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if len(zr.File) != 2 || zr.File[0].Name != "1.blk" || zr.File[1].Name != "2.blk" {
		t.Fatalf("archive holds %d entries", len(zr.File))
	}
}

// L1: closing by a stale reader never closes the connection that took the slot.
func TestL1_StaleCloseKeepsNewSlot(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	e.saveConnectionPort("SER", "127.0.0.1", 9001, nil, e.ReserveSlot())
	old := e.slotObj(1)
	e.CloseSlot(1)
	sl := e.saveConnectionPort("SER", "127.0.0.1", 9002, nil, e.ReserveSlot())
	e.closeSlotObj(sl, old)
	if e.Peer(sl).Tipo == "" || e.Peer(sl).ListeningPort != 9002 {
		t.Fatal("L1: a stale close ended the new connection")
	}
}

// M7: after `clearcfg 1` the empty marker is not a seed, and a new one is.
func TestM7_NullIsNotASeed(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	e.SetNodesArray("null:10.0.0.1;8080:")
	if len(e.nodesArr) != 1 || e.nodesArr[0].host != "10.0.0.1" {
		t.Fatalf("seeds %+v", e.nodesArr)
	}
	e.N.CFG.Save("NORMAL null:10.0.0.1;8080: null: null: null: x:")
	if l := e.NodesList(); len(l) != 1 || l[0] != "10.0.0.1:8080" {
		t.Fatalf("nodes %v", l)
	}
	e.SetNodesArray("127.0.0.1;8001:127.0.0.1;8002:")
	if len(e.nodesArr) != 2 {
		t.Fatal("two local nodes on different ports are two seeds")
	}
}

// A denied peer is disconnected, not dialled and not accepted.
func TestDenyPeer(t *testing.T) {
	a, b, _, _, _ := connected(t)
	_, port, _ := splitHostPort(a.ServerAddr())
	b.DenyPeer("127.0.0.1:" + port)
	if b.Peer(1).Tipo != "" {
		t.Fatal("denied peer still connected")
	}
	if b.ConnectClient("127.0.0.1", port) != 0 {
		t.Fatal("dialled a denied peer")
	}
	b.AllowPeer("all")
	if len(b.DeniedPeers()) != 0 {
		t.Fatal("allow all")
	}
}

// Honest data never closes a connection; invalid blocks do, after strikes.
func TestBlockAnswersStrikes(t *testing.T) {
	a, b, na, nb, _ := connected(t)
	for _, n := range []*node.Node{na, nb} {
		if err := n.SetProposers([]string{na.Wallet.At(0).PublicKey}); err != nil {
			t.Fatal(err)
		}
	}
	garbage := func() {
		var zb bytes.Buffer
		zw := zip.NewWriter(&zb)
		w, _ := zw.Create("1.blk")
		_, _ = w.Write([]byte("not a block"))
		_ = zw.Close()
		b.expectReply(1, "BLOCKS")
		_ = a.peers.slots[1].conn.WriteStream("BLOCKZIP", zb.Bytes())
	}
	for i := 0; i < maxStrikes-1; i++ {
		garbage()
		settle(a, b)
		if b.Peer(1).Tipo == "" {
			t.Fatalf("closed after %d invalid answers", i+1)
		}
	}
	garbage()
	waitClosed(t, b, a)
}

// An empty answer (a peer with nothing new) is normal and keeps the slot.
func TestEmptyBlockAnswerKeepsConnection(t *testing.T) {
	a, b, _, _, _ := connected(t)
	var zb bytes.Buffer
	_ = zip.NewWriter(&zb).Close()
	b.expectReply(1, "BLOCKS")
	_ = a.peers.slots[1].conn.WriteStream("BLOCKZIP", zb.Bytes())
	settle(a, b)
	if b.Peer(1).Tipo == "" {
		t.Fatal("an empty answer closed the connection")
	}
}

func TestPendingConnectionsBounded(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	for i := 0; i < maxPendingConns; i++ {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		if !e.trackConn(NewConn(a)) {
			t.Fatalf("refused connection %d", i)
		}
	}
	a, _ := net.Pipe()
	if e.trackConn(NewConn(a)) {
		t.Fatal("M8: no global cap on connections before the slot stage")
	}
	_ = codec.IntToStr
}

// Without a node to take it, an order is neither announced nor broadcast.
func TestSendOrderNeedsUpToDateNode(t *testing.T) {
	var ck clock
	e := NewEngine(mkNode(t, &ck))
	e.N.SetConStatus(1)
	if got := e.SendOrderToNode("NSLORDER x"); got != "ERROR 20" {
		t.Fatalf("got %q", got)
	}
}

// H-06: a masternode file is stored only with the voted full hash.
func TestMNFileNeedsFullHash(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	e := NewEngine(mkNode(t, &ck))
	before := e.N.MNFile.Hash()
	line := "PSK 2 0.4.4 1 MNFILE $8.8.4.4;8080;N1;N2;1;2;3;4;5:"
	e.processMNFile(line) // no vote at all
	if e.N.MNFile.Hash() != before {
		t.Fatal("masternode file stored without a vote")
	}
	e.setConsensusForTest(CFullMNs, "0123456789abcdef0123456789abcdef")
	e.processMNFile(line) // a vote for another file
	if e.N.MNFile.Hash() != before {
		t.Fatal("masternode file stored although its hash differs from the vote")
	}
}
