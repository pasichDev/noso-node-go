package node

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// bed is a small chain: k nodes that share a clock and a proposer list made of
// their own first wallet keys, in node order.
type bed struct {
	t     *testing.T
	now   *int64
	nodes []*Node
}

func newBed(t *testing.T, k int) *bed {
	now := new(int64)
	*now = int64(consensus.GenesysTimeStamp) + 600
	b := &bed{t: t, now: now}
	var keys []string
	for i := 0; i < k; i++ {
		n, err := New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
		if err != nil {
			t.Fatal(err)
		}
		n.SetClock(func() int64 { return *now })
		b.nodes = append(b.nodes, n)
		keys = append(keys, n.Wallet.At(0).PublicKey)
	}
	for _, n := range b.nodes {
		if err := n.SetProposers(keys); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// slot moves the shared clock past the next block boundary, by the out-of-turn
// grace period (a block of any proposer may then be accepted, as the tests
// build with whichever node is at hand), and returns the boundary.
func (b *bed) slot() int64 {
	t := (*b.now/600 + 1) * 600
	*b.now = t + OutOfTurnGrace
	return t
}

// buildAt makes n build its next block with an explicit (possibly past) time.
func (b *bed) buildAt(n *Node, ts int64) *BuildResult {
	b.t.Helper()
	r, err := n.BuildNewBlock(n.MyLastBlock()+1, ts, n.MyLastBlockHash(), "", "x")
	if err != nil || r == nil {
		b.t.Fatalf("build %d: %v %v", n.MyLastBlock()+1, r, err)
	}
	return r
}

// build makes node n build the next block at the next boundary.
func (b *bed) build(n *Node) *BuildResult {
	b.t.Helper()
	ts := b.slot()
	r, err := n.BuildNewBlock(n.MyLastBlock()+1, ts, n.MyLastBlockHash(), "", "x")
	if err != nil || r == nil {
		b.t.Fatalf("build %d: %v %v", n.MyLastBlock()+1, r, err)
	}
	return r
}

// pull makes dst take every block src has beyond (or different from) its own.
func pull(t *testing.T, dst, src *Node) {
	t.Helper()
	for i := 0; i < 400; i++ {
		first := dst.BlocksRequestFrom() + 1
		if first > src.MyLastBlock() {
			return
		}
		z, err := src.ZipBlocks(first)
		if err != nil {
			t.Fatal(err)
		}
		cnt, err := dst.StageBlocks(z)
		if err != nil && cnt == 0 && !dst.ForkProbe() {
			t.Fatalf("pull: %v", err)
		}
		if cnt == 0 && !dst.ForkProbe() {
			return
		}
	}
	t.Fatal("pull did not converge")
}

func sameState(t *testing.T, a, b *Node) {
	t.Helper()
	if a.MyLastBlock() != b.MyLastBlock() || a.MyLastBlockHash() != b.MyLastBlockHash() {
		t.Fatalf("tips differ: %d %s vs %d %s", a.MyLastBlock(), a.MyLastBlockHash(), b.MyLastBlock(), b.MyLastBlockHash())
	}
	if a.Summary.Hash() != b.Summary.Hash() || a.Headers.Hash() != b.Headers.Hash() ||
		a.GVTs.Hash() != b.GVTs.Hash() || a.PSOs.FileHash() != b.PSOs.FileHash() {
		t.Fatalf("state differs: summary %s/%s headers %s/%s gvts %s/%s psos %s/%s",
			a.Summary.Hash(), b.Summary.Hash(), a.Headers.Hash(), b.Headers.Hash(),
			a.GVTs.Hash(), b.GVTs.Hash(), a.PSOs.FileHash(), b.PSOs.FileHash())
	}
}

// pay puts a signed transfer from node's wallet 0 into the pool of every node.
func (b *bed) pay(from *Node, to string, amount, fee int64, nodes ...*Node) types.Order {
	b.t.Helper()
	w := from.Wallet.At(0)
	o, err := from.SendFundsFromAddress(w.Hash, to, amount, fee, "ref", strconv.FormatInt(*b.now-100, 10), 1)
	if err != nil {
		b.t.Fatal(err)
	}
	o.OrderID = SingleOrderID(o.TrfrID)
	for _, n := range nodes {
		if !n.AddPool(o) {
			b.t.Fatal("pool refused order")
		}
	}
	return o
}

// forge makes a block on top of n's tip with the given user orders (block
// form, keys parallel), correct in every respect except what the test breaks.
// It is sealed with n's proposer key.
func forge(t *testing.T, n *Node, ts int64, orders []types.Order, keys []string) *storage.Block {
	t.Helper()
	_, sw, ok := n.sealer()
	if !ok {
		t.Fatal("node is not a proposer")
	}
	prev := n.LastBlockData()
	num := prev.Number + 1
	var fees int64
	orders = append([]types.Order(nil), orders...)
	for i := range orders {
		orders[i].Block = int32(num)
		fees += orders[i].AmmountFee
	}
	dev, mnsPay, _, _, _ := consensus.Shares(num, consensus.GetBlockReward(num), fees, 0)
	if num >= consensus.PoSBlockEnd {
		orders = append(append([]types.Order(nil), orders...), createDevPaymentOrder(num, ts, dev, prev.Number))
		keys = append(append([]string(nil), keys...), "")
	}
	h := types.BlockHeader{Number: num, TimeStart: prev.TimeEnd + 1, TimeEnd: ts, TrxTotales: int32(len(orders)),
		LastBlockHash: n.MyLastBlockHash(), AccountMiner: crypto.GetAddressFromPublicKey(sw.PublicKey, 0),
		Reward: consensus.GetBlockReward(num), MinerFee: fees}
	h.TimeTotal = int32(h.TimeEnd - h.TimeStart)
	h.TargetHash = n.MyLastBlockHash()
	blk := &storage.Block{Header: h, Orders: orders, V2: true, Keys: keys, MNsPay: mnsPay}
	restamp(n, blk)
	sealBlock(blk, sw.PublicKey, sw.PrivateKey)
	return blk
}

// offer hands a block to a node the way a peer would.
func offer(n *Node, blk *storage.Block) (int, error) {
	return n.AcceptBlocks(map[int64][]byte{blk.Header.Number: blk.Encode()})
}

// signedOrder builds a block-form order signed by w.
func signedOrder(t *testing.T, w types.Wallet, typ, receiver, ref string, amount, fee, ts int64) (types.Order, string) {
	o := types.Order{OrderLines: 1, OrderType: typ, TimeStamp: ts, Reference: ref, TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: receiver, AmmountFee: fee, AmmountTrf: amount}
	SignOrder(crypto.ChainID, &o, w.PrivateKey)
	o.OrderID = SingleOrderID(o.TrfrID)
	o.Sender = o.Address
	return o, w.PublicKey
}

// restamp recomputes the state root a (possibly edited) block must carry:
// the block is applied to a scratch copy of the state, which is then put back.
// A block that does not apply keeps a placeholder root and is refused for the
// real reason first. The caller seals again.
func restamp(n *Node, blk *storage.Block) {
	num := blk.Header.Number
	if num >= 53000 {
		blk.Header.NxtBlkDiff = int32(len(blk.MNsAddrs))
	}
	blk.Header.Solution = solutionFor(strings.Repeat("0", 64), n.chainDigest())
	// The state root the block must carry: apply it to a scratch copy of the
	// state and put the state back. A block that does not apply keeps the
	// placeholder, which is refused for the real reason first.
	n.chainMu.Lock()
	if n.snapshot("forge") == nil {
		n.Summary.ResetBlockRecords()
		if moved, err := n.applyBlockState(blk); err == nil && n.Summary.UpdateChanges() == nil {
			n.Summary.SetLastOp(num)
			if n.persistDerived(num, moved) == nil {
				blk.Header.Solution = solutionFor(n.stateRoot(), n.chainDigest())
			}
		}
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot("forge")
		n.UpdateMyData()
		_ = os.RemoveAll(n.undoDir("forge"))
	}
	n.chainMu.Unlock()
}
