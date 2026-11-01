package node

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Tests of the final review round (final-consensus.md, final-operator.md,
// final-completeness.md). The names carry the finding.

func readF(p string) []byte { b, _ := os.ReadFile(p); return b }

// newFollower is a node that is not a proposer, on the bed's clock and list.
func newFollower(t *testing.T, b *bed) *Node {
	t.Helper()
	n, err := New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetClock(func() int64 { return *b.now })
	if err := n.SetProposers(b.nodes[0].Proposers()); err != nil {
		t.Fatal(err)
	}
	return n
}

func zipFrom(t *testing.T, s *Node, first int64) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := first; i <= first+100 && i <= s.MyLastBlock(); i++ {
		raw, err := os.ReadFile(s.Lay.BlockFile(i))
		if err != nil {
			break
		}
		w, _ := zw.Create(codec.IntToStr(i) + ".blk")
		_, _ = w.Write(raw)
	}
	_ = zw.Close()
	return b.Bytes()
}

// Operator walk, critical: a node that never builds kept every relayed order
// for ever, so its wallet saw stale pending payments and could not send twice.
func TestFinal_FollowerPrunesMinedOrders(t *testing.T) {
	b := newBed(t, 2)
	a := b.nodes[0]
	f := newFollower(t, b)
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, f, a)
	me := f.Wallet.At(0).Hash
	b.pay(a, me, 2000000000, 1000000, a, f)
	b.build(a)
	pull(t, f, a)
	if f.PendingCount() != 0 {
		t.Fatalf("follower pool holds %d mined orders", f.PendingCount())
	}
	for i := 0; i < 5; i++ {
		before := f.Summary.BalanceIndexed(me)
		o := b.pay(f, a.Wallet.At(0).Hash, 10000000, 1000000, a, f)
		if f.AddressPendingPays(me) != o.AmmountFee+o.AmmountTrf {
			t.Fatalf("round %d: pending %d", i, f.AddressPendingPays(me))
		}
		b.build(a)
		pull(t, f, a)
		if f.PendingCount() != 0 || a.PendingCount() != 0 {
			t.Fatalf("round %d: pools %d/%d after the block", i, f.PendingCount(), a.PendingCount())
		}
		if f.AddressPendingPays(me) != 0 || f.AddressAvailable(me) != f.Summary.BalanceIndexed(me) {
			t.Fatalf("round %d: stale pending payments %d", i, f.AddressPendingPays(me))
		}
		if f.Summary.BalanceIndexed(me) >= before {
			t.Fatalf("round %d: the payment was not mined", i)
		}
		if f.Wallet.At(0).Balance != f.Summary.BalanceIndexed(me) {
			t.Fatalf("round %d: wallet record balance %d, chain %d", i, f.Wallet.At(0).Balance, f.Summary.BalanceIndexed(me))
		}
	}
}

// The pool has a bound and a full pool refuses; it never evicts.
func TestFinal_PoolIsBounded(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	w := a.Wallet.At(0)
	ts := *b.now - 100
	dest, _ := addr(t)
	var first types.Order
	for i := 0; i < MaxPoolLines+5; i++ {
		o := types.Order{OrderLines: 1, OrderType: "TRFR", TimeStamp: ts + int64(i%50), Reference: "n" + strconv.Itoa(i), TrxLine: 1,
			Sender: w.PublicKey, Address: w.Hash, Receiver: dest.Hash, AmmountFee: 1, AmmountTrf: 11}
		SignOrder(crypto.ChainID, &o, w.PrivateKey)
		o.OrderID = SingleOrderID(o.TrfrID)
		o.Normalize()
		if i == 0 {
			first = o
		}
		ok := a.AddPool(o)
		if i < MaxPoolLines && !ok {
			t.Fatalf("order %d refused below the bound", i)
		}
		if i >= MaxPoolLines && ok {
			t.Fatalf("order %d admitted over the bound", i)
		}
	}
	if a.PendingCount() != MaxPoolLines || !a.TranxAlreadyPending(first.TrfrID) {
		t.Fatal("an admitted order was evicted")
	}
}

// final-consensus 1 / final-security F-3: an order that declares more lines
// than it carries swallowed the orders behind it, and nothing of it was mined.
func TestFinal_OrderLinesCannotSwallowOthers(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for i := 0; i < 4; i++ {
		b.build(a)
	}
	w := a.Wallet.At(0)
	att, _ := addr(t)
	v1, _ := addr(t)
	v2, _ := addr(t)
	ts := b.slot()
	var os_ []types.Order
	var ks []string
	for i, x := range []types.Wallet{att, v1, v2} {
		o, k := signedOrder(t, w, "TRFR", x.Hash, "ref"+strconv.Itoa(i), 1000000000, 10, ts-300)
		os_, ks = append(os_, o), append(ks, k)
	}
	if c, err := offer(a, forge(t, a, ts, os_, ks)); c != 1 {
		t.Fatal(c, err)
	}
	*b.now = ts + 200
	mk := func(x types.Wallet, ts int64, lines int32, to string) types.Order {
		o := types.Order{OrderLines: lines, OrderType: "TRFR", TimeStamp: ts, Reference: "null", TrxLine: 1,
			Sender: x.PublicKey, Address: x.Hash, Receiver: to, AmmountFee: 1000000, AmmountTrf: 5}
		SignOrder(crypto.ChainID, &o, x.PrivateKey) // the attacker signs the count it declares
		o.OrderID = crypto.GetOrderHash("1" + strconv.FormatInt(ts, 10) + o.TrfrID)
		o.Normalize()
		return o
	}
	wire := func(o types.Order) string { return PTCHeader(a) + "ORDER 1 $" + types.StringFromOrder(o) }
	tb := ts + 100
	ao := mk(att, tb-5, 3, v1.Hash) // sorts before the victims', claims 3 lines, carries 1
	v1o := mk(v1, tb, 1, v2.Hash)
	v2o := mk(v2, tb+1, 1, v1.Hash)
	if r := a.PTCOrder(wire(ao)); len(r) < 5 || r[:5] != "ERROR" {
		t.Fatalf("an order that declares 3 lines and carries 1 was admitted: %q", r)
	}
	for _, o := range []types.Order{v1o, v2o} {
		if r := a.PTCOrder(wire(o)); r == "" || r[:5] == "ERROR" {
			t.Fatal("honest order refused: ", r)
		}
	}
	// A pool that still holds such a group (admitted by an older version, or by
	// a bug) must not cost the lines behind it: they are judged one by one.
	a.poolMu.Lock()
	a.pool = append(a.pool, ao)
	a.poolMu.Unlock()
	a.poolMu.Lock()
	sortPool := a.pool
	for i := 1; i < len(sortPool); i++ {
		for j := i; j > 0 && sortPool[j].TimeStamp < sortPool[j-1].TimeStamp; j-- {
			sortPool[j], sortPool[j-1] = sortPool[j-1], sortPool[j]
		}
	}
	a.poolMu.Unlock()
	res, err := a.BuildNewBlock(a.MyLastBlock()+1, b.slot(), "", "", "")
	if err != nil || res == nil {
		t.Fatal(err)
	}
	if len(res.Block.Orders) != 2 {
		t.Fatalf("block holds %d orders, want the 2 honest ones", len(res.Block.Orders))
	}
}

// final-consensus 7: line 1 of a 2-line order cannot be executed alone, and
// the whole order can; SealOrder is how a sender makes one.
func TestFinal_PrefixOfMultiLineOrderRefused(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, f, a)
	w := a.Wallet.At(0)
	s2, _ := addr(t)
	r, _ := addr(t)
	ts := b.slot()
	o, k := signedOrder(t, w, "TRFR", s2.Hash, "fund", 1000000000, 0, ts-300)
	if c, err := offer(a, forge(t, a, ts, []types.Order{o}, []string{k})); c != 1 {
		t.Fatal(c, err)
	}
	pull(t, f, a)
	ts = b.slot()
	l1 := types.Order{OrderLines: 2, OrderType: "TRFR", TimeStamp: ts - 100, Reference: "inv", TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: r.Hash, AmmountFee: 10, AmmountTrf: 100}
	l2 := l1
	l2.TrxLine, l2.Sender, l2.Address = 2, s2.PublicKey, s2.Hash
	SignOrder(crypto.ChainID, &l1, w.PrivateKey)
	SignOrder(crypto.ChainID, &l2, s2.PrivateKey)
	// The proposer keeps line 1 and relabels the fields the old signature left out.
	cut := l1
	cut.OrderLines, cut.OrderID = 1, SingleOrderID(l1.TrfrID)
	key := cut.Sender
	cut.Sender = cut.Address
	if c, err := offer(f, forge(t, a, ts, []types.Order{cut}, []string{key})); c != 0 || err == nil {
		t.Fatalf("a prefix of a multi-line order was accepted: stored=%d err=%v", c, err)
	}
	if f.Summary.BalanceIndexed(r.Hash) != 0 {
		t.Fatal("the receiver was paid")
	}
	// The whole order passes.
	id := OrderGroupID([]types.Order{l1, l2})
	l1.OrderID, l2.OrderID = id, id
	g1, g2 := l1, l2
	g1.Sender, g2.Sender = g1.Address, g2.Address
	if c, err := offer(f, forge(t, a, ts, []types.Order{g1, g2}, []string{w.PublicKey, s2.PublicKey})); c != 1 {
		t.Fatalf("the complete order was refused: %v", err)
	}
	if got := f.Summary.BalanceIndexed(r.Hash); got != 200 {
		t.Fatalf("receiver has %d, want 200", got)
	}
}

// SealOrder: lines made one by one by SendFundsFromAddress become a wire order
// that the pool admits, the builder takes whole, and a follower accepts.
func TestFinal_SealOrderEndToEnd(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	w2, err := a.Wallet.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	ts := b.slot()
	o, k := signedOrder(t, a.Wallet.At(0), "TRFR", w2.Hash, "fund", 1000000000, 10, ts-300)
	if c, err := offer(a, forge(t, a, ts, []types.Order{o}, []string{k})); c != 1 {
		t.Fatal(c, err)
	}
	pull(t, f, a)
	dest, _ := addr(t)
	cur := strconv.FormatInt(*b.now-100, 10)
	l1, err := a.SendFundsFromAddress(a.Wallet.At(0).Hash, dest.Hash, 300000000, 1000000, "ref", cur, 1)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := a.SendFundsFromAddress(w2.Hash, dest.Hash, 200000000, 1000000, "ref", cur, 2)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := a.SealOrder([]types.Order{l1, l2})
	if err != nil {
		t.Fatal(err)
	}
	wire := PTCHeader(a) + "ORDER 2 $" + types.StringFromOrder(lines[0]) + " $" + types.StringFromOrder(lines[1])
	if r := a.PTCOrder(wire); r == "" || r[:5] == "ERROR" {
		t.Fatalf("sealed order refused: %q", r)
	}
	b.build(a)
	pull(t, f, a)
	if f.Summary.BalanceIndexed(dest.Hash) != 500000000 || f.PendingCount() != 0 {
		t.Fatalf("receiver %d, pool %d", f.Summary.BalanceIndexed(dest.Hash), f.PendingCount())
	}
}

// final-completeness GAP-1: nothing indexed mined orders, so lookup found none.
func TestFinal_MinedOrdersAreIndexed(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	for i := 0; i < 2; i++ {
		b.build(a)
	}
	pull(t, f, a)
	dest, _ := addr(t)
	o := b.pay(a, dest.Hash, 1000000000, 1000000, a, f)
	b.build(a)
	pull(t, f, a)
	for name, n := range map[string]*Node{"builder": a, "follower": f} {
		if got := n.OrderBlock(o.OrderID); got != int(n.MyLastBlock()) {
			t.Fatalf("%s: order is in block %d, lookup says %d", name, n.MyLastBlock(), got)
		}
		if l := n.MinedOrder(o.OrderID); len(l) != 1 || l[0].TrfrID != o.TrfrID {
			t.Fatalf("%s: lookup returned %v", name, l)
		}
	}
	// It survives a restart, and a rebuilt database agrees.
	n2, err := openAt(t, a.Lay.Root)
	if err != nil {
		t.Fatal(err)
	}
	if n2.OrderBlock(o.OrderID) != int(a.MyLastBlock()) {
		t.Fatal("lookup lost after restart")
	}
	_ = os.Remove(n2.Lay.BlocksDB)
	n3, err := openAt(t, a.Lay.Root)
	if err != nil {
		t.Fatal(err)
	}
	if n3.OrderBlock(o.OrderID) != int(a.MyLastBlock()) {
		t.Fatal("lookup not rebuilt from the chain")
	}
}

// ... and a reorganisation takes the records of the abandoned branch with it.
func TestFinal_ReorgRollsBackOrderIndex(t *testing.T) {
	b := newBed(t, 2)
	a, s := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, s, a)
	dest, _ := addr(t)
	o := b.pay(a, dest.Hash, 1000000000, 1000000, a)
	ts := b.slot()
	for SlotOf(ts)%2 != 1 {
		ts = b.slot()
	}
	b.buildAt(a, ts) // out of turn: lighter, holds the order
	if a.OrderBlock(o.OrderID) < 0 {
		t.Fatal("order not indexed in the lighter block")
	}
	b.buildAt(s, ts) // in turn: heavier, no order
	a.ProbeFork()
	pull(t, a, s)
	if a.MyLastBlockHash() != s.MyLastBlockHash() {
		t.Fatal("a did not adopt the heavier block")
	}
	if got := a.OrderBlock(o.OrderID); got != -1 {
		t.Fatalf("order of the abandoned block still found in block %d", got)
	}
	if len(a.DB.Blocks(o.OrderID)) != 0 || a.DB.Records() != 0 {
		t.Fatalf("records of the abandoned block remain in the database: %d", a.DB.Records())
	}
}

// final-completeness GAP-2: a chain born here had no GVT at all. The first
// block creates the 100 records for its sealer, the same way on every node.
func TestFinal_FirstBlockCreatesTheGVTs(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	if a.GVTs.Len() != 0 {
		t.Fatalf("genesis holds %d GVTs", a.GVTs.Len())
	}
	b.build(a)
	owner := a.Wallet.At(0).Hash
	if a.GVTs.Len() != 100 {
		t.Fatalf("%d GVTs after block 1", a.GVTs.Len())
	}
	for i, g := range a.GVTs.All() {
		if g.Number != strconv.Itoa(i) || g.Owner != owner || len(g.Hash) != 64 {
			t.Fatalf("record %d: %+v", i, g)
		}
	}
	h := a.GVTs.Hash()
	pull(t, f, a)
	if f.GVTs.Hash() != h {
		t.Fatal("a follower derived other GVTs")
	}
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, f, a)
	for _, n := range []*Node{a, f} {
		if err := n.RebuildSummary(); err != nil {
			t.Fatal(err)
		}
		if n.GVTs.Len() != 100 || n.GVTs.Hash() != h {
			t.Fatalf("rebuild lost or changed the GVTs: %d %s", n.GVTs.Len(), n.GVTs.Hash())
		}
	}
	sameState(t, a, f)
}

// A GVT moves through a block, a follower and a replay agree, and the admission
// accepts only the number the block rules read.
func TestFinal_SendGVTReferenceIsCanonical(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	w := a.Wallet.At(0) // the sealer of block 1 owns every GVT
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, f, a)
	dest, _ := addr(t)
	mk := func(ref string) types.Order {
		o := types.Order{OrderLines: 1, OrderType: "SNDGVT", TimeStamp: *b.now - 100, Reference: ref, TrxLine: 1,
			Sender: w.PublicKey, Address: w.Hash, Receiver: dest.Hash, AmmountFee: consensus.GetCustFee(a.MyLastBlock() + 1)}
		SignOrder(crypto.ChainID, &o, w.PrivateKey)
		o.OrderID = SingleOrderID(o.TrfrID)
		o.Normalize()
		return o
	}
	wire := func(o types.Order) string { return types.StringFromOrder(o) }
	if c := a.PTCSendGVT(wire(mk("05"))); c == 0 {
		t.Fatal("reference 05 admitted: the builder would drop it")
	}
	if c := a.PTCSendGVT(wire(mk("5"))); c != 0 {
		t.Fatalf("reference 5 refused: %d", c)
	}
	b.build(a)
	pull(t, f, a)
	if a.GVTs.Index(5).Owner != dest.Hash || f.GVTs.Index(5).Owner != dest.Hash {
		t.Fatal("GVT did not move")
	}
	sameState(t, a, f)
	// a replay reaches the same owners
	h := a.GVTs.Hash()
	if err := f.RebuildSummary(); err != nil || f.GVTs.Hash() != h {
		t.Fatalf("replay differs: %v", err)
	}
}

// final-consensus 5 / completeness 1: the unpaid masternode share goes to the
// miner, so the coins in existence are exactly the schedule.
func TestFinal_UnpaidMasternodeShareGoesToTheMiner(t *testing.T) {
	for _, h := range []int64{48010, 60000, 100000, 210001} {
		r := consensus.GetBlockReward(h)
		for _, mns := range []int{0, 1, 3, 7} {
			dev, pay, tot, pow, ok := consensus.Shares(h, r, 12345, mns)
			if !ok || dev+tot+pow != r+12345 || tot != pay*int64(mns) {
				t.Fatalf("block %d with %d masternodes: dev %d pay %d total %d pow %d", h, mns, dev, pay, tot, pow)
			}
		}
	}
	b := newBed(t, 1)
	a := b.nodes[0]
	h := int64(60000)
	b.fastForward(h, []string{a.Wallet.At(0).Hash}, []int64{1000000000})
	var before int64
	for _, s := range a.Summary.All() {
		before += s.Balance
	}
	b.build(a)
	var after int64
	for _, s := range a.Summary.All() {
		after += s.Balance
	}
	if after-before != consensus.GetBlockReward(h+1) {
		t.Fatalf("supply grew by %d, the block reward is %d", after-before, consensus.GetBlockReward(h+1))
	}
}

// final-consensus 4: a proposer sealing a slot that is not its own, early, took
// the slot from its turn holder.
func TestFinal_OutOfTurnBlockWaitsForTheGracePeriod(t *testing.T) {
	b := newBed(t, 2)
	rogue, honest := b.nodes[0], b.nodes[1]
	b.build(rogue)
	pull(t, honest, rogue)
	stolen := 0
	for i := 0; i < 4; i++ {
		s := b.slot()
		for honest.InTurn(s) == false {
			s = b.slot()
		}
		*b.now = s - 5
		if _, err := rogue.BuildNewBlock(rogue.MyLastBlock()+1, s, "", "", ""); err != nil {
			t.Fatal(err)
		}
		if c, err := honest.AcceptBlocks(map[int64][]byte{rogue.MyLastBlock(): readF(rogue.Lay.BlockFile(rogue.MyLastBlock()))}); c != 0 || err == nil {
			t.Fatalf("slot %d: early out-of-turn block accepted (%d, %v)", s, c, err)
		}
		*b.now = s
		if _, err := honest.BuildNewBlock(honest.MyLastBlock()+1, s, "", "", ""); err != nil {
			stolen++
			t.Logf("slot %d: %v", s, err)
		}
		// the honest block is the heavier one; the rogue follows it
		rogue.ProbeFork()
		pull(t, rogue, honest)
	}
	if stolen != 0 {
		t.Fatalf("%d slots taken by an out-of-turn block", stolen)
	}
	// After the grace period a stand-in is accepted: a missed slot is not lost.
	s := b.slot()
	for rogue.InTurn(s) {
		s = b.slot()
	}
	*b.now = s
	if _, err := rogue.BuildNewBlock(rogue.MyLastBlock()+1, s, "", "", ""); err != nil {
		t.Fatal(err)
	}
	blk := readF(rogue.Lay.BlockFile(rogue.MyLastBlock()))
	num := rogue.MyLastBlock()
	if c, err := honest.AcceptBlocks(map[int64][]byte{num: blk}); c != 0 || err == nil {
		t.Fatalf("early stand-in accepted: %d %v", c, err)
	}
	*b.now = s + OutOfTurnGrace
	if c, err := honest.AcceptBlocks(map[int64][]byte{num: blk}); c != 1 {
		t.Fatalf("stand-in after the grace period refused: %v", err)
	}
}

// final-consensus 3: a fork deeper than the probe windows was never found.
func TestFinal_DeepForksResolve(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	for _, depth := range []int{170, 330} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) {
			b := newBed(t, 2)
			a, s := b.nodes[0], b.nodes[1]
			*b.now += 600 * 1500
			tc := *b.now - *b.now%600 - 600*1300
			for i := 0; i < 400; i++ {
				b.buildAt(a, tc+int64(i)*600)
			}
			pull(t, s, a)
			t0 := tc + 600*400
			*b.now = t0 + 600*2000
			for i := 0; i < depth*2+1; i++ {
				b.buildAt(s, t0+int64(i)*600)
			}
			for i := 0; i < depth; i++ {
				b.buildAt(a, t0+int64(i)*1200)
			}
			for i := 0; i < 60 && a.MyLastBlockHash() != s.MyLastBlockHash(); i++ {
				from := a.BlocksRequestFrom()
				_, _ = a.StageBlocks(zipFrom(t, s, from+1))
			}
			if a.MyLastBlockHash() != s.MyLastBlockHash() {
				t.Fatalf("fork of depth %d not resolved: tip %d vs %d", depth, a.MyLastBlock(), s.MyLastBlock())
			}
		})
	}
}

// final-consensus 8: a staged sibling that lost made the next honest block
// look invalid.
func TestFinal_StaleStagedSiblingDoesNotPoisonTheNextBlock(t *testing.T) {
	b := newBed(t, 2)
	a, s := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, s, a)
	ts := b.slot()
	for SlotOf(ts)%2 != 0 {
		ts = b.slot()
	}
	b.buildAt(a, ts) // in turn for a, heavy
	x := s.MyLastBlock() + 1
	h := *b.now
	b.buildAt(s, ts) // lighter sibling
	sibling := readF(s.Lay.BlockFile(x))
	if c, err := a.AcceptBlocks(map[int64][]byte{x: sibling}); c != 0 {
		t.Fatalf("sibling stored: %d %v", c, err)
	}
	d := cpdir(t, a.Lay.Root)
	cl, _ := openAt(t, d)
	cl.SetClock(func() int64 { return h + 600 })
	if _, err := cl.BuildNewBlock(x+1, ts+600, "", "", ""); err != nil {
		t.Fatal(err)
	}
	*b.now = ts + 600 + OutOfTurnGrace
	st, err := a.StageBlocks(zipFrom(t, cl, a.BlocksRequestFrom()+1))
	if st != 1 || err != nil {
		t.Fatalf("next honest block: stored=%d err=%v", st, err)
	}
}

// final-security F-8: the staged branch is bounded in blocks and in bytes and
// the node does not keep asking for the same window.
func TestFinal_StagedBranchIsBounded(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	for _, mode := range []string{"blocks", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			oldN, oldB := maxStaged, maxStagedBytes
			defer func() { maxStaged, maxStagedBytes = oldN, oldB }()
			b := newBed(t, 2)
			a, s := b.nodes[0], b.nodes[1]
			b.build(a)
			pull(t, s, a)
			t0 := b.slot()
			*b.now = t0 + 600*5000
			for i := 0; i < 60; i++ {
				b.buildAt(a, t0+int64(i)*600) // heavy
			}
			for i := 0; i < 240; i++ {
				b.buildAt(s, t0+int64(i)*600*2) // long and light
			}
			if mode == "blocks" {
				maxStaged = 150
			} else {
				maxStagedBytes = 150 * int64(len(readF(s.Lay.BlockFile(s.MyLastBlock()))))
			}
			a.chainState.probeDepth = 1 << 30
			a.ProbeFork()
			var hit bool
			for i := 0; i < 20; i++ {
				_, err := a.StageBlocks(zipFrom(t, s, a.BlocksRequestFrom()+1))
				if err != nil && errors.Is(err, ErrInvalidBlock) && len(a.chainState.staged) == 0 {
					hit = true
					break
				}
				if len(a.chainState.staged) > 150 {
					t.Fatalf("staged %d blocks over the bound", len(a.chainState.staged))
				}
			}
			if !hit {
				t.Fatal("the bound was never reported and the stage never released")
			}
			if a.BlocksRequestFrom() != a.MyLastBlock() {
				t.Fatalf("request still points at %d", a.BlocksRequestFrom())
			}
		})
	}
}

// final-consensus 12: a damaged tip file is not a healthy start.
func TestFinal_DamagedTipIsAHardError(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	b.build(a)
	p := a.Lay.BlockFile(2)
	raw := readF(p)
	if err := os.WriteFile(p, raw[:len(raw)-10], 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := openAt(t, a.Lay.Root)
	if err == nil && !n.Corrupt() {
		t.Fatal("a truncated tip block passed the start check")
	}
	if n != nil {
		if _, err := n.BuildNewBlock(3, b.slot(), "", "", ""); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("a corrupt node builds: %v", err)
		}
	}
}

// An empty archive (a peer with nothing beyond what we asked for) is an answer
// like any other: no block, no panic, and the fork walk ends.
func TestFinal_EmptyArchiveIsHarmless(t *testing.T) {
	b := newBed(t, 2)
	a := b.nodes[0]
	b.build(a)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	_ = zw.Close()
	for _, probe := range []bool{false, true} {
		if probe {
			a.ProbeFork()
		}
		if c, err := a.StageBlocks(buf.Bytes()); c != 0 || err != nil {
			t.Fatalf("probe=%v: %d %v", probe, c, err)
		}
	}
	if a.ForkProbe() {
		t.Fatal("an empty answer left the fork walk running")
	}
}

// A link that fails while the walk is resuming ends the resumed walk instead of
// asking for the same window again.
func TestFinal_ProbeResumeIsClearedByAWindowThatDoesNotLink(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for i := 0; i < 5; i++ {
		b.build(a)
	}
	a.ProbeFork()
	a.chainState.mu.Lock()
	a.chainState.probeResume = 3
	a.chainState.mu.Unlock()
	a.deepenProbe()
	if a.chainState.probeResume != 0 {
		t.Fatal("probeResume survives a window that did not link")
	}
}

// final-consensus 12, second line of defence: a tip file that differs from the
// one the headers file recorded (here only in its seal text; signatures are
// deterministic now, F-9, so a second valid seal of the same block no longer
// exists) must not be called healthy at start.
func TestFinal_ResealedTipIsRepairedAtStart(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	b.build(a)
	blk, err := a.Blocks.Read(2)
	if err != nil {
		t.Fatal(err)
	}
	old := readF(a.Lay.BlockFile(2))
	tail := "AA"
	if strings.HasSuffix(blk.SealSig, tail) {
		tail = "BB"
	}
	blk.SealSig = blk.SealSig[:len(blk.SealSig)-2] + tail
	if bytes.Equal(blk.Encode(), old) {
		t.Fatal("the seal did not change")
	}
	if err := os.WriteFile(a.Lay.BlockFile(2), blk.Encode(), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := openAt(t, a.Lay.Root)
	if err != nil {
		t.Fatal(err)
	}
	if err := consistent(n); err != nil {
		t.Fatalf("the headers file still names the old tip block: %v", err)
	}
}

// final-security F-5: a report that names another node's IP and then fails the
// challenge must not take that node's slot.
func TestFinal_FailedReportDoesNotBurnTheIPSlot(t *testing.T) {
	b := newBed(t, 1)
	n := b.nodes[0]
	att := "PSK 2 v 1 $MNREPO 8.8.8.8 8080 attackersign"
	vic := "PSK 2 v 1 $MNREPO 8.8.8.8 8080 victimsign"
	n.AddWaitingMN(att)
	if n.PopWaitingMN() != att || n.IPMNAlreadyProcessed(att) {
		t.Fatal("the attacker's report was not queued, or marked before its challenge")
	}
	// its challenge failed: nothing is recorded
	n.AddWaitingMN(vic)
	if n.WaitingMNsLen() != 1 {
		t.Fatal("the victim's real report was refused: the IP slot was burnt")
	}
	line := n.PopWaitingMN()
	if n.IPMNAlreadyProcessed(line) {
		t.Fatal("the victim's report is already processed")
	}
	// its challenge succeeded: the slot is taken, a later report for the IP is not queued
	n.MarkIPMNProcessed(line)
	n.MarkMNIPReceived(line)
	n.AddWaitingMN(att)
	if n.WaitingMNsLen() != 0 || !n.IPMNAlreadyProcessed(att) {
		t.Fatal("an answered IP can be taken again")
	}
}

// A proposer that is down for several slots must not stop the pool: an order
// dated now is admitted although the tip is old; one dated far ahead is not.
func TestFinal_OrdersAreAdmittedWhileTheTipIsStale(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	*b.now += 600 * 5 // five slots without a block
	w := a.Wallet.At(0)
	dest, _ := addr(t)
	mk := func(ts int64) types.Order {
		o, err := a.SendFundsFromAddress(w.Hash, dest.Hash, 100000000, 1000000, "ref", strconv.FormatInt(ts, 10), 1)
		if err != nil {
			t.Fatal(err)
		}
		o.OrderID = SingleOrderID(o.TrfrID)
		return o
	}
	if c := a.ValidateTrfr(mk(*b.now-5), w.Hash); c != 0 {
		t.Fatalf("a current order is refused with code %d", c)
	}
	if c := a.ValidateTrfr(mk(*b.now+3600), w.Hash); c != 4 {
		t.Fatalf("a far-future order gets code %d, want 4", c)
	}
	if c := a.ValidateTrfr(mk(*b.now+OrderClockTolerance-1), w.Hash); c != 0 {
		t.Fatalf("an order inside the tolerance gets code %d", c)
	}
}

// An unsealed block is not a block of another branch, even with a wrong parent.
func TestFinal_UnsealedBlockIsDistinctFromAForkParent(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, f, a)
	ts := b.slot()
	blk := forge(t, a, ts, nil, nil)
	blk.Header.LastBlockHash = "NOT-OUR-PARENT"
	_, err := f.AcceptBlocks(map[int64][]byte{blk.Header.Number: blk.Encode()})
	if !errors.Is(err, ErrUnsealed) || errors.Is(err, ErrForkParent) {
		t.Fatalf("unsealed block with a wrong parent: %v", err)
	}
	_, sw, _ := a.sealer()
	sealBlock(blk, sw.PublicKey, sw.PrivateKey)
	_, err = f.AcceptBlocks(map[int64][]byte{blk.Header.Number: blk.Encode()})
	if !errors.Is(err, ErrForkParent) || errors.Is(err, ErrUnsealed) {
		t.Fatalf("sealed block with a wrong parent: %v", err)
	}
}
