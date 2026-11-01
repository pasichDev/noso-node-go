package network

import (
	"archive/zip"
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// Peer claims (final security review F-2, F-11). A PING is unauthenticated
// text: nothing a peer says about its height may stop a proposer building or
// decide whom the node asks for blocks.

func pipeSlot(e *Engine, ip string) int {
	c1, c2 := net.Pipe()
	go func() {
		b := make([]byte, 65536)
		for {
			if _, err := c2.Read(b); err != nil {
				return
			}
		}
	}()
	return e.saveConnectionPort("CLI", ip, -1, NewConn(c1), -1)
}

func claim(e *Engine, sl int, height, hash string) {
	e.ProcessPing("PSK 2 0.4.4zzz "+e.nowStr()+" $PING 1 "+height+" "+hash+" S 0 H 3 8080 M 0 null 0 G C P", sl, false)
}

func emptyZip(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := zip.NewWriter(&b).Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func claimNode(t *testing.T, ck *clock) (*node.Node, *Engine) {
	t.Helper()
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, ck)
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
	n.CFG.Save("NORMAL 203.0.113.9;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE:")
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	return n, e
}

// A peer that claims an impossible height and never delivers does not stop
// the proposer, whatever it claims and however often.
func TestClaimedHeightNeverStopsBuilding(t *testing.T) {
	var ck clock
	n, e := claimNode(t, &ck)
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
	n.UpdateOptions(func(o *node.StorageOptions) { o.BuildBlocks = true })
	honest := pipeSlot(e, "198.51.100.1")
	atk := pipeSlot(e, "198.51.100.66")
	for i := 0; i < 6; i++ {
		e.buildNMSBlock = consensus.NextBlockTimeStamp(n.UTCTime())
		ck.v.Store(e.buildNMSBlock + 1)
		claim(e, honest, codec.IntToStr(n.MyLastBlock()), n.MyLastBlockHash())
		claim(e, atk, "999999999999999", "F"+strconv.Itoa(i))
		e.VerifyConnectionStatus()
		before := n.MyLastBlock()
		e.Tick()
		if n.MyLastBlock() != before+1 {
			t.Fatalf("slot %d: proposer stopped at %d (status %d) by an unproven claim", i, before, n.ConStatus())
		}
		// the answer to the pull the claim caused is empty
		e.blocksReceived(atk, emptyZip(t))
	}
}

// A plausible claim is a hint: the status says "behind" while the sender is
// being asked, and goes back to up to date once the sender is caught giving
// nothing.
func TestPlausibleClaimHoldsStatusUntilStruck(t *testing.T) {
	var ck clock
	n, e := claimNode(t, &ck)
	honest := pipeSlot(e, "198.51.100.1")
	claim(e, honest, "0", n.MyLastBlockHash())
	e.VerifyConnectionStatus()
	if n.ConStatus() != 3 {
		t.Fatalf("control: status %d", n.ConStatus())
	}
	atk := pipeSlot(e, "198.51.100.66")
	claim(e, atk, "8", crypto.IDHash("x"))
	e.VerifyConnectionStatus()
	e.blocksReceived(atk, emptyZip(t)) // it had nothing
	e.VerifyConnectionStatus()
	if n.ConStatus() != 3 {
		t.Fatalf("a claim answered with nothing still holds the status at %d", n.ConStatus())
	}
}

// A claim above what the chain clock allows is never asked for.
func TestImpossibleClaimIsNeverPulled(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	atk := pipeSlot(e, "198.51.100.66")
	for i := 0; i < 20; i++ {
		ck.v.Add(11)
		claim(e, atk, "999999999999999", crypto.IDHash(strconv.Itoa(i)))
		e.syncBlocks()
		e.syncMu.Lock()
		got := e.pullSlot
		e.pullSlot = nil
		e.syncMu.Unlock()
		if got != nil {
			t.Fatalf("round %d: asked a peer for blocks that cannot exist", i)
		}
	}
}

// The peer asked for blocks is not the one with the highest claim: peers take
// turns, and one that answers with nothing is held back while the honest one
// keeps being asked.
func TestPullRotatesAndHoldsBackLiars(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	honest := pipeSlot(e, "198.51.100.1")
	atk := pipeSlot(e, "198.51.100.66")
	asked := map[int]int{}
	for i := 0; i < 40; i++ {
		ck.v.Add(11)
		claim(e, honest, "5", crypto.IDHash("honest"))
		claim(e, atk, "11", crypto.IDHash(strconv.Itoa(i))) // plausible, higher, new hash every time
		e.syncBlocks()
		e.syncMu.Lock()
		s := e.pullSlot
		e.syncMu.Unlock()
		switch s {
		case e.slotObj(honest):
			asked[honest]++
			e.syncMu.Lock()
			e.pullSlot = nil
			e.syncMu.Unlock()
		case e.slotObj(atk):
			asked[atk]++
			e.blocksReceived(atk, emptyZip(t)) // an empty answer
		}
	}
	t.Logf("asked: honest %d, liar %d", asked[honest], asked[atk])
	if asked[honest] == 0 {
		t.Fatal("the honest peer was never asked: the highest claim owns the pull")
	}
	if asked[atk] > 8 || asked[honest] < 25 {
		t.Fatalf("the liar was asked %d times and the honest peer %d in 40 rounds, empty answers cost it nothing", asked[atk], asked[honest])
	}
}

// Delivered valid blocks are counted per connection; a peer that delivered is
// preferred over one that only claims.
func TestEmptyAnswersAreStruck(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	atk := pipeSlot(e, "198.51.100.66")
	claim(e, atk, "9", crypto.IDHash("a"))
	e.syncBlocks()
	e.blocksReceived(atk, emptyZip(t))
	st := e.pullStateOf(e.slotObj(atk))
	if st.faults == 0 {
		t.Fatal("an empty answer to a claim was not struck")
	}
}

// A block with the wrong parent that no proposer sealed costs the sender.
func TestWrongParentGarbageIsStruck(t *testing.T) {
	var ck clock
	n, e := claimNode(t, &ck)
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
	sl := pipeSlot(e, "198.51.100.66")
	var b storage.Block
	b.Header.Number = 1
	b.Header.LastBlockHash = "NOTTHEPARENT"
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("1.blk")
	_, _ = w.Write(b.Encode())
	_ = zw.Close()
	for i := 0; i < 4; i++ {
		e.blocksReceived(sl, zb.Bytes())
	}
	st := e.pullStateOf(e.slotObj(sl))
	if st.faults < 2 {
		t.Fatalf("garbage with a wrong parent was struck %d times", st.faults)
	}
	claim(e, sl, "3", crypto.IDHash("tip"))
	e.syncBlocks()
	e.syncMu.Lock()
	got := e.pullSlot
	e.syncMu.Unlock()
	if got != nil {
		t.Fatal("a peer that sent garbage was asked again at once")
	}
}

// A peer that claims a tip and answers empty does not poison the same tip
// for the peers that really hold it.
func TestRejectedTipIsPerPeer(t *testing.T) {
	var ck clock
	n, e := claimNode(t, &ck)
	liar := pipeSlot(e, "198.51.100.66")
	h := crypto.IDHash("sibling")
	claim(e, liar, "0", h)
	e.syncBlocks()
	e.blocksReceived(liar, emptyZip(t))
	real := pipeSlot(e, "198.51.100.1")
	claim(e, real, "0", h)
	ck.v.Add(400)
	claim(e, liar, "0", n.MyLastBlockHash())
	claim(e, real, "0", h)
	e.syncMu.Lock()
	e.pullSlot = nil
	e.syncMu.Unlock()
	e.syncBlocks()
	e.syncMu.Lock()
	got := e.pullSlot
	e.syncMu.Unlock()
	if got != e.slotObj(real) {
		t.Fatal("a tip rejected on the liar's connection is ignored on the connection that really holds it")
	}
}

// F-11: inbound connections never take the slots outbound dialling needs.
func TestInboundCannotFillEverySlot(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	for i := 0; i < MaxConnections; i++ {
		ip := "198.51." + strconv.Itoa(i+1) + ".7" // a network of its own each
		c1, c2 := net.Pipe()
		go func() { _, _ = c2.Read(make([]byte, 1)) }()
		_ = e.saveConnectionPort("CLI", ip, -1, NewConn(c1), -1)
	}
	if e.freeSlot() == 0 {
		t.Fatal("99 inbound peers left no slot to dial out")
	}
	if e.ReserveSlot() == 0 {
		t.Fatal("outbound reservation failed")
	}
}

// F-11: one network (a /24, an IPv6 /64) gets a few inbound slots, not all.
func TestInboundLimitedPerNetwork(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	got := 0
	for i := 1; i <= 40; i++ {
		c1, c2 := net.Pipe()
		go func() { _, _ = c2.Read(make([]byte, 1)) }()
		if e.saveConnectionPort("CLI", "198.51.100."+strconv.Itoa(i), -1, NewConn(c1), -1) > 0 {
			got++
		}
	}
	got6 := 0
	for i := 1; i <= 40; i++ {
		c1, c2 := net.Pipe()
		go func() { _, _ = c2.Read(make([]byte, 1)) }()
		if e.saveConnectionPort("CLI", "2001:db8:1:2::"+strconv.Itoa(i), -1, NewConn(c1), -1) > 0 {
			got6++
		}
	}
	if got > 4 || got6 > 4 {
		t.Fatalf("one /24 took %d inbound slots, one /64 took %d", got, got6)
	}
}

// -bind / init-network -host: the peer listener binds the address it is told
// to, not every interface.
func TestServerBindsTheConfiguredAddress(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	e.BindAddr = "127.0.0.1"
	if err := e.StartServer(0); err != nil {
		t.Fatal(err)
	}
	if a := e.ServerAddr(); !strings.HasPrefix(a, "127.0.0.1:") {
		t.Fatalf("listening on %q, not on loopback only", a)
	}
}

// Nodes of one machine share the loopback address, so a per-address rate limit
// cannot tell them apart: at -clock-scale the nodes poll each other's status
// every fraction of a second and the limit starved the consensus.
func TestHeavyLimitSkipsLoopbackNotStrangers(t *testing.T) {
	var ck clock
	_, e := claimNode(t, &ck)
	for i := 0; i < 100; i++ {
		if !e.heavyOK("127.0.0.1") || !e.heavyOK("::1") {
			t.Fatalf("request %d from loopback refused", i)
		}
	}
	ok := 0
	for i := 0; i < 30; i++ {
		if e.heavyOK("198.51.100.9") {
			ok++
		}
	}
	if ok != 10 {
		t.Fatalf("a stranger got %d heavy requests a minute, want 10", ok)
	}
}

// F-5: one stake queues one report per block, not one per IP it names.
func TestOneStakeQueuesOneReport(t *testing.T) {
	var ck clock
	ck.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	atk, _ := reporter(t, &ck, "8.8.8.1")
	n.Summary.ResetBlockRecords()
	n.Summary.CreditTo(atk.N.Options().MNFunds, consensus.GetStackRequired(1), 0)
	if err := n.Summary.UpdateChanges(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"} {
		atk.N.UpdateOptions(func(o *node.StorageOptions) { o.MNIP = ip })
		e.queueMNReport(atk.ProtocolLine(13))
	}
	if got := n.WaitingMNsLen(); got != 1 {
		t.Fatalf("one stake queued %d reports", got)
	}
}
