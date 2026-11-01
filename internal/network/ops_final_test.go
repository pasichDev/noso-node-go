package network

import (
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// fundedNode: a node whose first wallet address is the only proposer and has
// mined a block (so it holds the reward), the clock inside the next period.
func fundedNode(t *testing.T) (*clock, *node.Node, *Engine, types.Wallet) {
	t.Helper()
	var ck clock
	ck.v.Store(1699999920)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	w := n.Wallet.At(0)
	if err := n.SetProposers([]string{w.PublicKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.BuildNewBlock(n.MyLastBlock()+1, 1699999800, n.MyLastBlockHash(), w.Hash, "x"); err != nil {
		t.Fatal(err)
	}
	return &ck, n, e, w
}

func ownGVT(t *testing.T, n *node.Node, num int, w types.Wallet) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/gvts.psk")
	if err != nil {
		t.Fatal(err)
	}
	n.GVTs.Replace(raw)
	n.GVTs.Reload()
	n.GVTs.ChangeOwner(num, n.GVTs.Index(num).Owner, w.Hash)
}

func buildNext(t *testing.T, ck *clock, n *node.Node, miner string) int {
	t.Helper()
	ck.v.Store(1699999800 + 720)
	res, err := n.BuildNewBlock(n.MyLastBlock()+1, 1699999800+600, n.MyLastBlockHash(), miner, "x")
	if err != nil || res == nil {
		t.Fatal(err)
	}
	return len(res.Block.Orders)
}

// sendgvt: from the console to the chain. The order is admitted with the
// canonical reference, a peer's dispatcher takes it, and a real block moves
// the GVT.
func TestSendGVTEndToEnd(t *testing.T) {
	ck, n, e, w := fundedNode(t)
	ownGVT(t, n, 5, w)
	if o := n.GVTs.Index(5); o.Number == "5" {
		t.Skip("the fixture already holds a canonical number") // the file keeps "05"
	}
	dest := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	sl := e.saveConnectionPort("CLI", "198.51.100.7", 8080, nil, -1)
	var said []string
	id := e.SendGVT("sendgvt 5 "+dest, func(s string) { said = append(said, s) })
	if id == "" || n.PendingCount() != 1 {
		t.Fatalf("not admitted: id %q pool %d said %v", id, n.PendingCount(), said)
	}
	if got := n.PendingCopy()[0].Reference; got != "5" {
		t.Fatalf("reference %q is not the canonical number", got)
	}
	// the announcement reaches a peer's dispatcher, which knows $SNDGVT
	var line string
	select {
	case line = <-e.slotObj(sl).out:
	default:
		t.Fatal("nothing was announced to the peers")
	}
	if codec.ASCIIUpper(codec.Parameter(line, 4)) != "$SNDGVT" {
		t.Fatalf("announced as %q", codec.Parameter(line, 4))
	}
	_, n2, e2, _ := fundedNode(t)
	ownGVT(t, n2, 5, n.Wallet.At(0))
	_ = n2
	var logs []string
	e2.Log = func(ch, m string) { logs = append(logs, m) }
	sl2 := e2.saveConnectionPort("CLI", "198.51.100.8", 8080, nil, -1)
	e2.addIncoming(sl2, line)
	e2.ParseProtocolLines()
	for _, l := range logs {
		if strings.Contains(l, "Unknown command") {
			t.Fatalf("the dispatcher dropped the transfer: %s", l)
		}
	}
	// a real block takes it
	if got := buildNext(t, ck, n, w.Hash); got != 1 {
		t.Fatalf("the block holds %d orders", got)
	}
	if owner := n.GVTs.Index(5).Owner; owner != dest {
		t.Fatalf("GVT 5 belongs to %s, not to the receiver", owner)
	}
}

// customize: the funds are read from the summary, the order goes through the
// pool into a block, and the alias exists afterwards.
func TestCustomizeEndToEnd(t *testing.T) {
	ck, n, e, w := fundedNode(t)
	if n.Summary.BalanceIndexed(w.Hash) < consensus.GetCustFee(n.MyLastBlock()+1) {
		t.Fatal("setup: no funds")
	}
	var said []string
	if !e.Customize("customize "+w.Hash+" goodalias", func(s string) { said = append(said, s) }) {
		t.Fatalf("refused: %v", said)
	}
	if n.PendingCount() != 1 {
		t.Fatalf("pool %d", n.PendingCount())
	}
	if got := buildNext(t, ck, n, w.Hash); got != 1 {
		t.Fatalf("the block holds %d orders", got)
	}
	if !n.AliasAlreadyExists("goodalias") {
		t.Fatal("the alias does not exist after the block")
	}
	// the same alias, or the same address again, is refused with a reason
	said = nil
	if e.Customize("customize "+w.Hash+" otheralias", func(s string) { said = append(said, s) }) {
		t.Fatalf("customized twice: %v", said)
	}
}

func TestCustomizeWithoutFundsSaysSo(t *testing.T) {
	var ck clock
	ck.v.Store(1699999920)
	n := mkNode(t, &ck)
	e := NewEngine(n)
	t.Cleanup(e.Stop)
	var said []string
	if e.Customize("customize "+n.Wallet.At(0).Hash+" goodalias", func(s string) { said = append(said, s) }) {
		t.Fatal("an empty address customized")
	}
	if !strings.Contains(strings.Join(said, "|"), "Insufficient balance") {
		t.Fatalf("said %v", said)
	}
}

// F-10: a reference with separators cannot start a second entry in
// getpendingorders.
func TestPendingRawInfoCannotBeForged(t *testing.T) {
	_, n, _, w := fundedNode(t)
	o := types.Order{OrderLines: 1, OrderType: "CUSTOM", TimeStamp: 1699999921, TrxLine: 1,
		Reference: "x\x7fa,1,TRFR,b,N3DthVsfEUtqrgWFHTEB6F88xLkT3Df,99900000000,1,r", Sender: w.PublicKey, Address: w.Hash,
		Receiver: "goodalias", AmmountFee: consensus.GetCustFee(n.MyLastBlock() + 1)}
	node.SignOrder(&o, w.PrivateKey)
	o.OrderID = node.SingleOrderID(o.TrfrID)
	if !n.AddPool(o) {
		t.Skip("the pool already refuses such an order")
	}
	raw := strings.TrimSpace(PendingRawInfo(n, true))
	if strings.Count(raw, " ") != 0 || strings.Count(raw, ",") != 7 {
		t.Fatalf("forged entry: %q", raw)
	}
}
