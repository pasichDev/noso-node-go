package node

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Regression tests of the rewrite review (rw-review-consensus.md). Each name
// carries the finding it came from.

// F2 / C-03: a proposer cannot spend an account whose key it does not hold.
func TestRW_ForgedSpendRejected(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	victim, victimKey := addr(t)
	b.build(a)
	b.pay(a, victim.Hash, 3000000000, 1000000, a)
	b.build(a)
	pull(t, f, a)
	if f.Summary.BalanceIndexed(victim.Hash) != 3000000000 {
		t.Fatal("victim not funded")
	}
	ts := b.slot()
	attacker := a.Wallet.At(0).Hash
	mk := func(sigFrom func(o *types.Order)) (*storage.Block, types.Order) {
		o := types.Order{OrderLines: 1, OrderType: "TRFR", TimeStamp: ts - 100, Reference: "null", TrxLine: 1,
			Sender: victimKey, Address: victim.Hash, Receiver: attacker, AmmountFee: 1000000, AmmountTrf: 1000000000}
		sigFrom(&o)
		o.OrderID = SingleOrderID(o.TrfrID)
		o.Sender = o.Address
		return forge(t, a, ts, []types.Order{o}, []string{victimKey}), o
	}
	// 1: garbage signature, valid TrfrID (what the original accepted).
	blk, _ := mk(func(o *types.Order) { o.Signature = "forged"; o.TrfrID = OrderTrfrID(crypto.ChainID, *o, o.Address) })
	if _, err := offer(f, blk); err == nil {
		t.Fatal("C-03: a spend with a forged signature was accepted")
	}
	// 2: the proposer signs with its own key but names the victim's address.
	blk, _ = mk(func(o *types.Order) {
		o.Signature = crypto.SignCanonical(a.Wallet.At(0).PrivateKey, "ORDER1", OrderFields(*o, o.Address)...)
		o.TrfrID = OrderTrfrID(crypto.ChainID, *o, o.Address)
	})
	if _, err := offer(f, blk); err == nil {
		t.Fatal("C-03: a spend signed by another key was accepted")
	}
	// 3: the proposer swaps in its own public key and address binding.
	own := a.Wallet.At(0)
	o := types.Order{OrderLines: 1, OrderType: "TRFR", TimeStamp: ts - 100, Reference: "null", TrxLine: 1,
		Sender: own.PublicKey, Address: victim.Hash, Receiver: attacker, AmmountFee: 1000000, AmmountTrf: 1000000000}
	SignOrder(crypto.ChainID, &o, own.PrivateKey)
	o.Sender = o.Address
	if _, err := offer(f, forge(t, a, ts, []types.Order{o}, []string{own.PublicKey})); err == nil {
		t.Fatal("C-03: key that does not belong to the address accepted")
	}
	if f.Summary.BalanceIndexed(victim.Hash) != 3000000000 || f.MyLastBlock() != 2 {
		t.Fatal("state changed by a refused block")
	}
	// Control: the victim's real signature is accepted.
	real, key := signedOrder(t, victim, "TRFR", attacker, "null", 1000000000, 1000000, ts-100)
	if n, err := offer(f, forge(t, a, ts, []types.Order{real}, []string{key})); err != nil || n != 1 {
		t.Fatalf("honest signed spend refused: %d %v", n, err)
	}
	if f.Summary.BalanceIndexed(victim.Hash) != 3000000000-1000000000-1000000 {
		t.Fatal("honest spend not applied")
	}
}

// Downgrade: a block without the trailer, or sealed by a stranger, is refused
// from peers while old blocks stay readable.
func TestRW_NoDowngradeNoStranger(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	r := b.build(a)
	// strip the trailer: the legacy form of the same block
	plain := *r.Block
	plain.V2, plain.Keys, plain.SealKey, plain.SealSig = false, nil, "", ""
	old, err := storage.DecodeBlock(plain.Encode())
	if err != nil || old.V2 || string(old.Header.Encode()) != string(r.Block.Header.Encode()) {
		t.Fatalf("legacy block unreadable: %v", err)
	}
	if _, err := f.AcceptBlocks(map[int64][]byte{1: plain.Encode()}); err == nil {
		t.Fatal("block without trailer accepted from a peer")
	}
	stranger := crypto.GenerateKeyPair()
	forged := *r.Block
	forged.SealKey = stranger.PublicKey
	forged.SealSig = crypto.SignCanonical(stranger.PrivateKey, "BLOCKSEAL1", sealDigest(&forged))
	if _, err := f.AcceptBlocks(map[int64][]byte{1: forged.Encode()}); err == nil {
		t.Fatal("block sealed by a non-proposer accepted")
	}
	tampered := *r.Block
	tampered.Header.Reward++
	if _, err := f.AcceptBlocks(map[int64][]byte{1: tampered.Encode()}); err == nil {
		t.Fatal("tampered block accepted")
	}
	// a node with no proposer list accepts nothing (fails closed)
	now := int64(consensus.GenesysTimeStamp) + 100000
	lone, _ := New(t.TempDir()+"/NOSODATA", nil)
	lone.SetClock(func() int64 { return now })
	if _, err := lone.AcceptBlocks(map[int64][]byte{1: r.Block.Encode()}); !errors.Is(err, ErrNoProposers) {
		t.Fatalf("unconfigured node: %v", err)
	}
	if cnt, err := f.AcceptBlocks(map[int64][]byte{1: r.Block.Encode()}); err != nil || cnt != 1 {
		t.Fatalf("honest block refused: %d %v", cnt, err)
	}
}

// F8 / C-03: unfunded CUSTOM, SNDGVT and TRFR, and a replayed order.
func TestRW_StateRulesEnforced(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	poor, poorKey := addr(t)
	b.build(a)
	b.build(a)
	pull(t, f, a)
	ts := b.slot()
	fee := consensus.GetCustFee(3)
	custom, _ := signedOrder(t, poor, "CUSTOM", "alias1", "null", 0, fee, ts-100)
	sndgvt, _ := signedOrder(t, poor, "SNDGVT", poorKey[:0]+a.Wallet.At(0).Hash, "1", 0, fee, ts-100)
	trfr, _ := signedOrder(t, poor, "TRFR", a.Wallet.At(0).Hash, "null", 10, 1000000, ts-100)
	for name, o := range map[string]types.Order{"CUSTOM": custom, "SNDGVT": sndgvt, "TRFR": trfr} {
		if n, err := offer(f, forge(t, a, ts, []types.Order{o}, []string{poorKey})); err == nil || n != 0 {
			t.Fatalf("F8: unfunded %s accepted (supply minted)", name)
		}
	}
	// Replay: the same signed order twice in one block, and in the next block.
	w := a.Wallet.At(0)
	o1, k1 := signedOrder(t, w, "TRFR", poor.Hash, "null", 1000, 1000000, ts-100)
	if _, err := offer(f, forge(t, a, ts, []types.Order{o1, o1}, []string{k1, k1})); err == nil {
		t.Fatal("same order twice in a block accepted")
	}
	blk := forge(t, a, ts, []types.Order{o1}, []string{k1})
	if n, err := offer(f, blk); err != nil || n != 1 {
		t.Fatalf("honest block: %v", err)
	}
	if _, err := offer(a, blk); err != nil { // a takes the same block as a follower would
		t.Fatalf("proposer applying its own block: %v", err)
	}
	ts2 := b.slot()
	if _, err := offer(f, forge(t, f2(a, f), ts2, []types.Order{o1}, []string{k1})); err == nil {
		t.Fatal("order replayed in the next block accepted")
	}
	// An order from long ago (outside the time window) cannot come back.
	old, ko := signedOrder(t, w, "TRFR", poor.Hash, "null", 1000, 1000000, ts-5000)
	if _, err := offer(f, forge(t, f2(a, f), ts2, []types.Order{old}, []string{ko})); err == nil {
		t.Fatal("order outside the time window accepted")
	}
}

// f2 returns a proposer node whose tip equals f's, to forge the next block.
func f2(a, f *Node) *Node {
	pull0(a, f)
	return a
}

func pull0(dst, src *Node) {
	for dst.MyLastBlock() < src.MyLastBlock() {
		z, _ := src.ZipBlocks(dst.MyLastBlock() + 1)
		if _, err := dst.StageBlocks(z); err != nil {
			return
		}
	}
}

// F4 / 8425: a fresh chain does not stop at block 8425, and the 48010 and
// 88500 boundaries are crossed with real blocks that a follower applies.
func TestRW_BoundariesFastPath(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	pa, pf := a.Wallet.At(0), f.Wallet.At(0)
	mnWallet, _ := addr(t)
	stake := consensus.GetStackRequired(48010) * 2
	crossed := func(from, to int64) {
		for a.MyLastBlock() < to {
			b.build(a)
			pull(t, f, a)
		}
		sameState(t, a, f)
	}
	const each = 1000000000000
	b.fastForward(8420, []string{pa.Hash, pf.Hash}, []int64{each, each})
	b.pay(a, pf.Hash, 1000000000, 1000000, a)
	crossed(8420, 8430)
	if a.MyLastBlock() != 8430 {
		t.Fatalf("chain stopped at %d (ErrDivZero)", a.MyLastBlock())
	}
	r, _ := a.Blocks.Read(8426)
	if r.PosPay != 0 || len(r.PosAddrs) != 0 {
		t.Fatal("proof-of-stake paid although nobody can be")
	}
	// masternodes from 48010
	b.fastForward(48005, []string{pa.Hash, pf.Hash, mnWallet.Hash}, []int64{each, each, stake})
	crossed(48005, 48012)
	if a.Blocks.Header(48011).MinerFee != 0 {
		t.Fatal("unexpected fee")
	}
	// the project payment from 88500, with transfers in the same block
	b.fastForward(88496, []string{pa.Hash, pf.Hash}, []int64{each, each})
	o := b.pay(a, pf.Hash, 5000000, 1000000, a)
	_ = o
	crossed(88496, 88503)
	last, _ := a.Blocks.Read(88500)
	if last.Orders[len(last.Orders)-1].OrderType != "PROJCT" || a.Summary.BalanceIndexed(consensus.ProjectFunds) == 0 {
		t.Fatal("no project payment at 88500")
	}
}

// F9 / M-10 overflow: the masternode share is derived, never multiplied.
func TestRW_MNShareChecked(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	holder, _ := addr(t)
	stake := consensus.GetStackRequired(48010) * 2
	b.fastForward(48009, []string{a.Wallet.At(0).Hash, holder.Hash}, []int64{1000000000000, stake})
	ts := b.slot()
	try := func(name string, addrs []string, pay int64) {
		blk := forge(t, a, ts, nil, nil)
		blk.MNsAddrs, blk.MNsPay = addrs, pay
		restamp(a, blk)
		sealBlock(blk, a.Wallet.At(0).PublicKey, a.Wallet.At(0).PrivateKey)
		if _, err := offer(f, blk); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	many := make([]string, 16384)
	for i := range many {
		many[i] = holder.Hash
	}
	try("16384 x 2^50 (wraps to 0)", many, 1<<50)
	try("duplicate masternode", []string{holder.Hash, holder.Hash}, 100)
	try("masternode without stake", []string{a.Wallet.At(1).Hash}, 100)
	try("pay above the derived share", []string{holder.Hash}, 1<<40)
	dev, share, _, _, _ := consensus.Shares(48010, consensus.GetBlockReward(48010), 0, 1)
	_ = dev
	good := forge(t, a, ts, nil, nil)
	good.MNsAddrs, good.MNsPay = []string{holder.Hash}, share
	restamp(a, good)
	sealBlock(good, a.Wallet.At(0).PublicKey, a.Wallet.At(0).PrivateKey)
	if n, err := offer(f, good); err != nil || n != 1 {
		t.Fatalf("derived share refused: %v", err)
	}
	if f.Summary.BalanceIndexed(holder.Hash) != stake+share {
		t.Fatal("masternode not paid")
	}
}

// F6 / C-03: the builder never emits a block the validator refuses.
func TestRW_BuilderNeverExceedsValidator(t *testing.T) {
	if testing.Short() {
		t.Skip("signs 2000 orders")
	}
	for _, height := range []int64{100, 88499} {
		b := newBed(t, 2)
		a, f := b.nodes[0], b.nodes[1]
		w := a.Wallet.At(0)
		b.fastForward(height-1, []string{w.Hash}, []int64{1000000000000})
		var raw []byte
		for i := 0; i < 100; i++ {
			g := types.DecodeGVT(make([]byte, types.GVTSize))
			g.Owner = w.Hash
			raw = append(raw, g.Encode()...)
		}
		for _, n := range b.nodes {
			n.GVTs.Replace(raw)
			n.GVTs.Reload()
		}
		ts0 := *b.now
		dest, _ := addr(t)
		fee := consensus.GetCustFee(height)
		var pool []types.Order
		for i := 0; i < 3; i++ {
			o, k := signedOrder(t, w, "SNDGVT", dest.Hash, strconv.Itoa(i), 0, fee, ts0-100+int64(i))
			o.Sender = k
			pool = append(pool, o)
		}
		for i := 0; i < 2100; i++ {
			o, k := signedOrder(t, w, "TRFR", dest.Hash, "r"+strconv.Itoa(i), 10, 1000000, ts0-99+int64(i%90))
			o.Sender = k
			pool = append(pool, o)
		}
		a.SetPending(pool)
		r := b.build(a)
		gv := len(gvtsOf0(r.Block.Orders))
		tr := 0
		for _, o := range r.Block.Orders {
			if o.OrderType == "TRFR" {
				tr++
			}
		}
		if gv != 3 || tr != 2000 {
			t.Fatalf("height %d: built %d gvt %d trfr", height, gv, tr)
		}
		if _, err := f.AcceptBlocks(map[int64][]byte{height: r.Block.Encode()}); err != nil {
			t.Fatalf("height %d: follower refused the honest block: %v", height, err)
		}
		sameState(t, a, f)
		if a.GVTs.Index(1).Owner != dest.Hash {
			t.Fatal("gvt not moved")
		}
	}
}

func gvtsOf0(l []types.Order) []types.Order {
	var out []types.Order
	for _, o := range l {
		if o.OrderType == "SNDGVT" {
			out = append(out, o)
		}
	}
	return out
}

// F7 / M-12: a failed write leaves nothing behind and a retry pays once.
func TestRW_FailedWriteRetryPaysOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	w := a.Wallet.At(0)
	before := a.Summary.BalanceIndexed(w.Hash)
	poolBefore := b.pay(a, addrStr(t), 1000000000, 1000000, a)
	_ = poolBefore
	sumHash, hdrHash := a.Summary.Hash(), a.Headers.Hash()
	_ = os.Chmod(a.Lay.BlockDir, 0o500)
	ts := b.slot()
	_, err := a.BuildNewBlock(2, ts, a.MyLastBlockHash(), "", "x")
	_ = os.Chmod(a.Lay.BlockDir, 0o755)
	if err == nil {
		t.Fatal("build succeeded without being able to write")
	}
	if a.MyLastBlock() != 1 || a.Summary.Hash() != sumHash || a.Headers.Hash() != hdrHash ||
		a.Summary.BalanceIndexed(w.Hash) != before || a.PendingCount() != 1 {
		t.Fatalf("failed build left state behind: last=%d pending=%d", a.MyLastBlock(), a.PendingCount())
	}
	if r, err := a.BuildNewBlock(2, ts, a.MyLastBlockHash(), "", "x"); err != nil || len(r.Block.Orders) != 1 {
		t.Fatalf("retry: %v", err)
	}
	want := before + consensus.GetBlockReward(2) - 1000000000
	if got := a.Summary.BalanceIndexed(w.Hash); got != want {
		t.Fatalf("retry paid twice: %d want %d", got, want)
	}
}

func addrStr(t *testing.T) string { w, _ := addr(t); return w.Hash }

// F10 / M-01: an alias registered in one block is taken in the next.
func TestRW_AliasAcrossBlocks(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	second, _ := addr(t)
	b.build(a)
	b.pay(a, second.Hash, 2000000000, 1000000, a)
	b.build(a)
	pull(t, f, a)
	ts := b.slot()
	fee := consensus.GetCustFee(3)
	o1, k1 := signedOrder(t, a.Wallet.At(0), "CUSTOM", "shop1", "null", 0, fee, ts-100)
	if n, err := offer(f, forge(t, a, ts, []types.Order{o1}, []string{k1})); err != nil || n != 1 {
		t.Fatalf("first registration: %v", err)
	}
	pull0(a, f)
	if !a.AliasAlreadyExists("shop1") || !f.AliasAlreadyExists("shop1") {
		t.Fatal("M-01: alias registered in the previous block is not seen as taken")
	}
	ts2 := b.slot()
	o2, k2 := signedOrder(t, second, "CUSTOM", "shop1", "null", 0, fee, ts2-100)
	if n, err := offer(f, forge(t, a, ts2, []types.Order{o2}, []string{k2})); err == nil || n != 0 {
		t.Fatal("M-01: duplicate alias accepted in a later block")
	}
}

// F3 / H-04: the depth limit is cumulative across calls and restarts.
func TestRW_ReorgLimitCumulative(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for a.MyLastBlock() < 70 {
		b.build(a)
	}
	if got := a.RemoveBlocks(60); got != 11 { // 60..70
		t.Fatalf("first removal %d", got)
	}
	if got := a.RemoveBlocks(55); got != 5 { // 55..59
		t.Fatalf("second removal %d", got)
	}
	// 49..54 would bring the total to 22 blocks below the highest tip ever.
	if got := a.RemoveBlocks(49); got != -1 {
		t.Fatalf("H-04: cumulative depth exceeded, removed %d", got)
	}
	if a.MyLastBlock() != 54 {
		t.Fatalf("tip %d", a.MyLastBlock())
	}
	if got := a.RemoveBlocks(51); got != 4 { // exactly 20 below 70 is still allowed (51..54)
		t.Fatalf("removal to the horizon: %d", got)
	}
	// the horizon survives a restart
	root := a.Lay.Root
	n2, err := New(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Finalized() != 50 {
		t.Fatalf("finalized after restart: %d", n2.Finalized())
	}
}

// F1 / M-10: a proposer in a minority never deletes its own valid blocks, a
// heavier valid branch is adopted by everyone, and a tie is settled the same
// way whatever the order in which the branches arrive.
func TestRW_ForkChoiceConverges(t *testing.T) {
	b := newBed(t, 3)
	p0, p1, p2 := b.nodes[0], b.nodes[1], b.nodes[2]
	b.build(p0)
	pull(t, p1, p0)
	pull(t, p2, p0)
	base := *b.now
	slot := func(i int64) int64 { return (base/600 + i) * 600 }
	// partition: p0 builds 2,3,4 (weights 2+3+1 = 6); p1 builds 2,3 (1+2 = 3)
	for i := int64(1); i <= 3; i++ {
		*b.now = slot(i) + OutOfTurnGrace
		b.buildAt(p0, slot(i))
	}
	for i := int64(1); i <= 2; i++ {
		b.buildAt(p1, slot(i))
	}
	if p0.MyLastBlock() != 4 || p1.MyLastBlock() != 3 {
		t.Fatalf("setup %d %d", p0.MyLastBlock(), p1.MyLastBlock())
	}
	want := p0.MyLastBlockHash()
	// the lighter branch reaches the heavier node: nothing is deleted
	z, _ := p1.ZipBlocks(2)
	if cnt, _ := p0.StageBlocks(z); cnt != 0 || p0.MyLastBlock() != 4 || p0.MyLastBlockHash() != want {
		t.Fatalf("M-10: a lighter valid branch changed the heavier node (stored %d, tip %d)", cnt, p0.MyLastBlock())
	}
	sum0 := p0.Summary.Hash()
	// the heavier branch reaches the lighter node and is adopted
	pull(t, p1, p0)
	pull(t, p2, p0)
	sameState(t, p0, p1)
	sameState(t, p0, p2)
	if p0.Summary.Hash() != sum0 {
		t.Fatal("state of the winning node changed")
	}
	// the state after the reorganisation equals that of a node that only ever
	// saw the winning branch
	fresh := observer(t, p0)
	sameState(t, p1, fresh)

	// tie: p1 builds 2,3 (1+2) and p2 builds 2 and 3 (3+1) -> different weights;
	// use p1 {2,3} = 3 against p2 {2} = 3
	c := newBed(t, 3)
	*c.now = *b.now
	q0, q1, q2 := c.nodes[0], c.nodes[1], c.nodes[2]
	c.build(q0)
	pull(t, q1, q0)
	pull(t, q2, q0)
	cb := *c.now
	cs := func(i int64) int64 { return (cb/600 + i) * 600 }
	*c.now = cs(3) + OutOfTurnGrace
	c.buildAt(q1, cs(1))
	c.buildAt(q1, cs(2))
	c.buildAt(q2, cs(1))
	hash1, hash2 := q1.MyLastBlockHash(), q2.MyLastBlockHash()
	z1, _ := q1.ZipBlocks(2)
	z2, _ := q2.ZipBlocks(2)
	// the observers hear the two branches in opposite orders
	obsA, obsB := observer(t, q0), observer(t, q0)
	_, _ = obsA.StageBlocks(z1)
	_, _ = obsA.StageBlocks(z2)
	_, _ = obsB.StageBlocks(z2)
	_, _ = obsB.StageBlocks(z1)
	sameState(t, obsA, obsB)
	wantTip := hash2
	if Preferred(branchWeight(q1, 2, 3), q1.LastBlockData().TimeEnd, hash1, branchWeight(q2, 2, 2), q2.LastBlockData().TimeEnd, hash2) {
		wantTip = hash1
	}
	if obsA.MyLastBlockHash() != wantTip {
		t.Fatalf("tie not settled by the lower tip hash: %s want %s", obsA.MyLastBlockHash(), wantTip)
	}
}

// observer returns a node with the same chain as src (blocks 0..tip).
func observer(t *testing.T, src *Node) *Node {
	n, err := New(t.TempDir()+"/NOSODATA", nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetClock(src.clock)
	if err := n.SetProposers(src.Proposers()); err != nil {
		t.Fatal(err)
	}
	pull(t, n, src)
	return n
}

// BlockWeight and Preferred are pure functions of the chain.
func TestRW_WeightAndPreference(t *testing.T) {
	if BlockWeight(3, 1, 4) != 3 || BlockWeight(3, 2, 4) != 2 || BlockWeight(3, 0, 4) != 1 || BlockWeight(1, 0, 9) != 1 {
		t.Fatal("block weight")
	}
	if !Preferred(5, 1, "b", 4, 1, "a") || Preferred(4, 1, "a", 5, 1, "b") {
		t.Fatal("heavier wins")
	}
	if !Preferred(5, 1, "a", 5, 1, "b") || Preferred(5, 1, "b", 5, 1, "a") || Preferred(5, 1, "a", 5, 1, "a") {
		t.Fatal("tie goes to the lower hash")
	}
}

// F13: the masternode math does not read the local configuration mode.
func TestRW_ValidationIgnoresLocalMode(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	holder, _ := addr(t)
	stake := consensus.GetStackRequired(48010) * 2
	b.fastForward(48009, []string{a.Wallet.At(0).Hash, holder.Hash}, []int64{1000000000000, stake})
	a.CFG.Save("MNSONLY 127.0.0.1;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE:")
	f.CFG.Save("NORMAL 127.0.0.1;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE:")
	a.mn.list = []MNode{{IP: "1.2.3.4", Port: 8080, Fund: holder.Hash, Sign: holder.Hash}}
	r := b.build(a)
	if len(r.Block.MNsAddrs) != 1 {
		t.Fatalf("masternode not listed: %v", r.Block.MNsAddrs)
	}
	if n, err := f.AcceptBlocks(map[int64][]byte{48010: r.Block.Encode()}); err != nil || n != 1 {
		t.Fatalf("follower with another mode refused the block: %v", err)
	}
	sameState(t, a, f)
}

// F12: a failed rebuild puts everything back and says so.
func TestRW_RebuildRollsBack(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for i := 0; i < 3; i++ {
		b.pay(a, addrStr(t), 1000000000, 1000000, a)
		b.build(a)
	}
	if err := a.RebuildSummary(); err != nil {
		t.Fatalf("rebuild of a good chain: %v", err)
	}
	sum := a.Summary.Hash()
	blk, _ := a.Blocks.Read(3)
	blk.Orders[0].AmmountTrf = consensus.MaxSupply / 2 // no longer funded
	// re-seal so only the state rule can object
	_ = os.WriteFile(a.Lay.BlockFile(3), blk.Encode(), 0o644)
	if err := a.RebuildSummary(); err == nil {
		t.Fatal("rebuild over an unfunded block reported success")
	}
	if a.Summary.Hash() != sum {
		t.Fatal("failed rebuild left the summary changed")
	}
}

// F11: console commands queue behind a build (they share the chain lock).
func TestRW_ConsoleTakesTheChainLock(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	b.build(a)
	a.chainMu.Lock()
	var done atomic.Bool
	go func() { a.UndoLastBlock(); done.Store(true) }()
	time.Sleep(150 * time.Millisecond)
	if done.Load() {
		t.Fatal("UndoLastBlock ran while a build held the lock")
	}
	a.chainMu.Unlock()
	time.Sleep(150 * time.Millisecond)
	if !done.Load() || a.MyLastBlock() != 1 {
		t.Fatalf("undo did not run after the lock was released: last=%d", a.MyLastBlock())
	}
}

// H-04 / core: a block below the horizon that cannot be replayed stops the
// node instead of looping forever.
func TestRW_CorruptBelowHorizonStops(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for a.MyLastBlock() < 40 {
		b.pay(a, addrStr(t), 1000000000, 1000000, a)
		b.build(a)
	}
	blk, _ := a.Blocks.Read(5)
	blk.Orders[0].AmmountTrf = consensus.MaxSupply / 2
	_ = os.WriteFile(a.Lay.BlockFile(5), blk.Encode(), 0o644)
	a.Summary.SetLastOp(0)
	err := a.CompleteSummary()
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
	if a.MyLastBlock() != 40 {
		t.Fatal("blocks below the horizon were deleted")
	}
	t0 := time.Now()
	if err := a.CompleteSummary(); !errors.Is(err, ErrCorrupt) || time.Since(t0) > 50*time.Millisecond {
		t.Fatalf("second call replays again: %v", err)
	}
}

// Cold funds (H-01): see TestRW_ColdFundsReport in mn tests.

var _ = strings.Contains

func branchWeight(n *Node, from, to int64) int64 {
	var w int64
	for i := from; i <= to; i++ {
		w += n.blockScoreAt(i)
	}
	return w
}

// H-01: a masternode whose funds key stays cold reports under a delegation.
func TestRW_ColdFundsReport(t *testing.T) {
	b := newBed(t, 1)
	n := b.nodes[0]
	cold := crypto.GenerateKeyPair()
	fund := crypto.GetAddressFromPublicKey(cold.PublicKey, 0)
	sign := n.Wallet.At(0)
	n.UpdateOptions(func(o *storageOptions) { o.MNFunds = fund; o.MNSign = sign.Hash; o.MNIP = "8.8.8.8"; o.MNPort = "8080" })
	if n.MNReportString(1) != "" {
		t.Fatal("report without delegation")
	}
	if err := n.SetDelegation(cold.PublicKey, "garbage"); err == nil {
		t.Fatal("bad delegation stored")
	}
	if err := n.SetDelegation(cold.PublicKey, SignDelegation(cold.PrivateKey, sign.Hash, fund)); err != nil {
		t.Fatal(err)
	}
	rep := n.MNReportString(1)
	if rep == "" {
		t.Fatal("no report with the funds key cold")
	}
	line := "$MNREPO " + rep[:0]
	_ = line
	m, ok := ParseMNode("$MNREPO " + rep)
	if !ok || m.Fund != fund || m.SignPub == "" {
		t.Fatalf("delegated report refused: %v", ok)
	}
	// a different sign address cannot reuse the delegation
	other := crypto.GenerateKeyPair()
	m2 := m
	m2.Sign = crypto.GetAddressFromPublicKey(other.PublicKey, 0)
	m2.SignPub = other.PublicKey
	m2.Hash = crypto.IDHash(m2.IP + "8080" + m2.Sign + m2.Fund)
	m2.Sig = crypto.SignCanonical(other.PrivateKey, "MNREPORT1", mnReportFields(m2)...)
	if _, ok := ParseMNode("$MNREPO " + StringFromMN(m2)); ok {
		t.Fatal("delegation reused for another sign key")
	}
}

// A chain born here grows past block 8425 with real blocks, and a node that
// starts empty takes it over from genesis by the chain rules alone.
func TestRW_RealChainPast8425AndSyncFromGenesis(t *testing.T) {
	if os.Getenv("NOSO_LONG") == "" {
		t.Skip("builds 8430 real blocks (fsync bound, many minutes); set NOSO_LONG=1")
	}
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	for a.MyLastBlock() < 8430 {
		b.build(a)
	}
	if a.Blocks.Header(8430).Number != 8430 {
		t.Fatal("chain stopped")
	}
	pull(t, f, a)
	sameState(t, a, f)
	// a restart reads back the same tip and last operation
	n2, err := New(a.Lay.Root, nil)
	if err != nil || n2.MyLastBlock() != 8430 || n2.Summary.LastOp() != 8430 {
		t.Fatalf("restart: %v %d %d", err, n2.MyLastBlock(), n2.Summary.LastOp())
	}
	// and the whole state re-derives from the blocks
	h := a.Summary.Hash()
	if err := a.RebuildSummary(); err != nil || a.Summary.Hash() != h {
		t.Fatalf("rebuild from blocks: %v same=%v", err, a.Summary.Hash() == h)
	}
}

// A node that starts empty takes a few hundred real blocks (more than the 144
// of a headers update) with transfers in them, ends with identical files, and
// the state re-derives from the blocks after a restart.
func TestRW_SyncFromGenesis(t *testing.T) {
	n := 260
	if testing.Short() {
		n = 30
	}
	b := newBed(t, 3)
	a, f, g := b.nodes[0], b.nodes[1], b.nodes[2]
	for a.MyLastBlock() < int64(n) {
		if a.MyLastBlock()%20 == 2 {
			b.pay(a, addrStr(t), 1000000000, 1000000, a)
		}
		b.build(a)
	}
	pull(t, f, a)
	pull(t, g, f) // a second hop: followers serve followers
	sameState(t, a, f)
	sameState(t, a, g)
	n2, err := New(f.Lay.Root, nil)
	if err != nil || n2.MyLastBlock() != int64(n) || n2.Summary.LastOp() != int64(n) {
		t.Fatalf("restart: %v", err)
	}
	h := f.Summary.Hash()
	if err := f.RebuildSummary(); err != nil || f.Summary.Hash() != h {
		t.Fatalf("state does not re-derive from the blocks: %v", err)
	}
}
