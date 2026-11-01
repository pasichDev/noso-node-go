package node

import (
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func zipBlocksOf(t *testing.T, blocks map[int64][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for num, raw := range blocks {
		w, _ := zw.Create(codec.IntToStr(num) + ".blk")
		_, _ = w.Write(raw)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// re2 consensus 3 / security H-1: a block re-encoded by a third party
// (junk in the signature text, a stuffed DER) is refused on the path a peer's
// archive takes (StageBlocks), whatever hash it would have.
func TestRE2_ReencodedBlockRefused(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	raw := mustRead(t, a.Lay.BlockFile(1))
	blk, _ := storage.DecodeBlock(raw)
	orig := blk.SealSig
	f, _ := New(t.TempDir()+"/NOSODATA", nil)
	f.SetClock(func() int64 { return *b.now })
	if err := f.SetProposers(a.Proposers()); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{orig + "!", "!" + orig, orig[:10] + "\n" + orig[10:], orig[:10] + "*" + orig[10:], orig + "===="} {
		c := *blk
		c.SealSig = v
		cnt, err := f.StageBlocks(zipBlocksOf(t, map[int64][]byte{1: c.Encode()}))
		if cnt != 0 || err == nil {
			t.Fatalf("variant %q stored=%d err=%v", v[len(v)-6:], cnt, err)
		}
	}
	if cnt, err := f.StageBlocks(zipBlocksOf(t, map[int64][]byte{1: raw})); cnt != 1 || err != nil {
		t.Fatalf("original: %d %v", cnt, err)
	}
	// Same for a changed byte anywhere else in the file: the hash is the
	// identity of the exact bytes, and the seal covers all but the seal.
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	g, _ := New(t.TempDir()+"/NOSODATA", nil)
	g.SetClock(func() int64 { return *b.now })
	_ = g.SetProposers(a.Proposers())
	if cnt, _ := g.StageBlocks(zipBlocksOf(t, map[int64][]byte{1: bad})); cnt != 0 {
		t.Fatal("flipped bit accepted")
	}
}

// re2 consensus 2 / storage 2: state ahead of the chain after a crash is
// noticed at start, the chain wins, and a redelivered block applies once.
func TestRE2_CrashSummaryAheadHeals(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, f, a)
	b.pay(a, f.Wallet.At(0).Hash, 1000000, 10, a)
	b.build(a)
	raw := mustRead(t, a.Lay.BlockFile(4))
	if c, err := f.AcceptBlocks(map[int64][]byte{4: raw}); c != 1 || err != nil {
		t.Fatal(c, err)
	}
	good := a.Summary.Hash()
	// Crash point: state written, block and header record not.
	f.Blocks.Delete(4)
	f.Headers.RemoveLast()
	g, err := New(f.Lay.Root, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.SetClock(func() int64 { return *b.now })
	if g.MyLastBlock() != 3 || g.Summary.LastOp() != 3 {
		t.Fatalf("after restart tip %d lastop %d", g.MyLastBlock(), g.Summary.LastOp())
	}
	c, err := g.AcceptBlocks(map[int64][]byte{4: raw})
	if c != 1 || err != nil {
		t.Fatalf("redelivered block: %d %v", c, err)
	}
	if g.Summary.Hash() != good {
		t.Fatal("state differs from the honest node: block applied twice or not at all")
	}
	sameState(t, a, g)
}

// A change interrupted after the commit point (stage-2 journal) is finished
// at the next start; one interrupted before it is discarded. Both leave
// chain and state equal.
func TestRE2_JournalRecovery(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	for i := 0; i < 2; i++ {
		b.build(a)
	}
	pull(t, f, a)
	b.pay(a, f.Wallet.At(0).Hash, 1000000, 10, a)
	b.build(a)
	raw := mustRead(t, a.Lay.BlockFile(3))
	blk, _ := storage.DecodeBlock(raw)
	// Stage 2 durable, nothing else written, state already applied.
	f.chainMu.Lock()
	prev := f.LastBlockData()
	if err := f.snapshot("c3"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.evalBlock(blk, prev, f.MyLastBlockHash(), map[string]bool{}, "c3"); err != nil {
		t.Fatal(err)
	}
	if err := f.commitJournal("c3", 2, 3, map[int64][]byte{3: raw}, nil); err != nil {
		t.Fatal(err)
	}
	f.chainMu.Unlock()
	g, err := New(f.Lay.Root, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.SetClock(func() int64 { return *b.now })
	if g.MyLastBlock() != 3 {
		t.Fatalf("journalled block not completed: tip %d", g.MyLastBlock())
	}
	sameState(t, a, g)
	if storage.Exists(g.journalPath()) {
		t.Fatal("journal left behind")
	}
}

// re2 consensus 5: the proposer that comes next cannot replace the block of
// the proposer before it: skipping the slot costs weight, and at equal weight
// the earlier block keeps its place, however the hash falls.
func TestRE2_TipSnipeFails(t *testing.T) {
	b := newBed(t, 3)
	turn := func(n *Node, idx int64) int64 {
		ts := b.slot()
		for SlotOf(ts)%3 != idx {
			ts = b.slot()
		}
		return ts
	}
	victim, sniper := b.nodes[0], b.nodes[1]
	ts := turn(victim, 0)
	b.buildAt(victim, ts)
	vHash := victim.MyLastBlockHash()
	// The sniper forges the same height on the same parent in the next slot.
	pull(t, sniper, victim)
	sniper.chainMu.Lock()
	sniper.undoLastLocked()
	sniper.chainMu.Unlock()
	if sniper.MyLastBlock() != 0 {
		t.Fatal("setup")
	}
	ts2 := turn(sniper, 1)
	b.buildAt(sniper, ts2)
	z, _ := sniper.ZipBlocks(1)
	if c, _ := victim.StageBlocks(z); c != 0 || victim.MyLastBlockHash() != vHash {
		t.Fatalf("victim's block was replaced (stored %d)", c)
	}
}

// re2 consensus 4a: finality is not local. Two nodes whose tips differ by one
// end on the same chain when a heavier branch that forks deep is released.
func TestRE2_NoFinalitySplit(t *testing.T) {
	b := newBed(t, 3)
	p0, p1, p2 := b.nodes[0], b.nodes[1], b.nodes[2]
	turn := func(n *Node, idx int64) {
		ts := b.slot()
		for SlotOf(ts)%3 != idx {
			ts = b.slot()
		}
		b.buildAt(n, ts)
	}
	for i := 0; i < 3; i++ {
		turn(p0, 0)
	}
	pull(t, p1, p0)
	pull(t, p2, p0)
	fork := p0.MyLastBlock()
	save := *b.now
	for i := 0; i < 20; i++ {
		turn(p0, 0)
	}
	pull(t, p1, p0)
	turn(p0, 0) // p0 is one block ahead of p1
	end := *b.now
	*b.now = save
	for i := 0; i < 69; i++ {
		ts := b.slot()
		if ts > end+600*3 {
			break
		}
		if r, err := p2.BuildNewBlock(p2.MyLastBlock()+1, ts, p2.MyLastBlockHash(), "", "x"); err != nil || r == nil {
			t.Fatal(err)
		}
	}
	*b.now = end + 600*3
	for _, n := range []*Node{p0, p1} {
		pull(t, n, p2)
	}
	if p0.MyLastBlockHash() != p1.MyLastBlockHash() {
		t.Fatalf("split: %d %s vs %d %s (fork %d)", p0.MyLastBlock(), p0.MyLastBlockHash(), p1.MyLastBlock(), p1.MyLastBlockHash(), fork)
	}
	sameState(t, p0, p1)
}

// re2 consensus 6: replay commits block by block like forward validation, so
// a masternode funded in h+1 and paid in h+2 is accepted and rebuilt.
func TestRE2_RebuildAcceptsValidMN(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	h := int64(60000)
	req := consensus.GetStackRequired(h + 10)
	w := a.Wallet.At(0)
	mw, _ := addr(t)
	b.fastForward(h, []string{w.Hash}, []int64{req * 2})
	*b.now += 600
	ts := b.slot()
	o, key := signedOrder(t, w, "TRFR", mw.Hash, "ref", req, 10, ts-100)
	blk := forge(t, a, ts, []types.Order{o}, []string{key})
	if c, err := offer(a, blk); c != 1 {
		t.Fatal(c, err)
	}
	pull(t, f, a)
	ts = b.slot()
	blk2 := forge(t, a, ts, nil, nil)
	blk2.MNsAddrs = []string{mw.Hash}
	_, blk2.MNsPay, _, _, _ = consensus.Shares(h+2, consensus.GetBlockReward(h+2), 0, 1)
	restamp(a, blk2)
	_, sw, _ := a.sealer()
	sealBlock(blk2, sw.PublicKey, sw.PrivateKey)
	if c, err := offer(f, blk2); c != 1 {
		t.Fatalf("forward validation refused: %d %v", c, err)
	}
	// The fast-forwarded history has no real chain below h, so replay the two
	// blocks from the snapshot the way a reorg to h+1 does.
	f.chainMu.Lock()
	defer f.chainMu.Unlock()
	if err := f.restoreSnapshot(codec.IntToStr(h + 1)); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int64{h + 1, h + 2} {
		if err := f.addBlockToSummaryLocked(i, true); err != nil {
			t.Fatalf("replay of block %d: %v", i, err)
		}
	}
}

// re2 consensus 9: a masternode at exactly the stake is paid by the builder
// and accepted by the follower.
func TestRE2_MNStakeAgrees(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	h := int64(60000)
	mw, _ := addr(t)
	stake := consensus.GetStackRequired(h)
	b.fastForward(h, []string{mw.Hash}, []int64{stake})
	*b.now += 600
	a.mn.mu.Lock()
	a.mn.list = []MNode{{IP: "1.2.3.4", Port: 8080, Sign: mw.Hash, Fund: mw.Hash}}
	a.mn.mu.Unlock()
	ts := b.slot()
	if r, err := a.BuildNewBlock(h+1, ts, a.MyLastBlockHash(), "", "x"); err != nil || r == nil {
		t.Fatal(err)
	}
	raw := mustRead(t, a.Lay.BlockFile(h+1))
	if c, err := f.AcceptBlocks(map[int64][]byte{h + 1: raw}); err != nil {
		t.Fatalf("honest block refused: %d %v", c, err)
	}
}

// re2 consensus 7: the proposer list is fixed by the chain. A node with
// another list refuses block 1, a rewritten file cannot be loaded, and an
// empty or unreadable one is a hard error.
func TestRE2_ProposerListBound(t *testing.T) {
	b := newBed(t, 2)
	a := b.nodes[0]
	b.build(a)
	if err := a.SetProposers([]string{b.nodes[1].Wallet.At(0).PublicKey, a.Wallet.At(0).PublicKey}); err == nil {
		t.Fatal("list changed on a chain with blocks")
	}
	other, _ := New(t.TempDir()+"/NOSODATA", nil)
	other.SetClock(func() int64 { return *b.now })
	kp := crypto.GenerateKeyPair()
	_ = other.SetProposers([]string{a.Wallet.At(0).PublicKey, kp.PublicKey})
	z, _ := a.ZipBlocks(1)
	if c, err := other.StageBlocks(z); c != 0 || err == nil {
		t.Fatalf("block of another chain accepted: %d %v", c, err)
	}
	pf := a.Lay.Root + "/proposers.txt"
	orig := mustRead(t, pf)
	for name, content := range map[string]string{"empty": "", "other": kp.PublicKey + "\n", "junk": "not a key\n"} {
		writeFile(t, pf, []byte(content))
		if _, err := New(a.Lay.Root, nil); err == nil {
			t.Fatalf("%s proposers.txt loaded", name)
		}
	}
	_ = os.Remove(pf)
	if _, err := New(a.Lay.Root, nil); err == nil {
		t.Fatal("missing proposers.txt on a chain with blocks loaded")
	}
	writeFile(t, pf, orig)
	if _, err := New(a.Lay.Root, nil); err != nil {
		t.Fatal(err)
	}
}

// re2 security M-4, as decided: the proposers are trusted, so the masternode
// list is not a check on them. What is not paid to listed masternodes stays
// with the miner (as in the original) and nothing is burnt.
func TestRE2_MNShareNotCaptured(t *testing.T) {
	r := consensus.GetBlockReward(100000)
	dev, _, _, powNone, _ := consensus.Shares(100000, r, 0, 0)
	if powNone != r-dev {
		t.Fatalf("with no masternode listed the miner earns %d, the block pays %d beyond the project share", powNone, r-dev)
	}
	for _, n := range []int{1, 7, 100} {
		d, pay, tot, pow, _ := consensus.Shares(100000, r, 0, n)
		if d+tot+pow != r || tot != pay*int64(n) || pow < powNone-tot-int64(n) {
			t.Fatalf("%d masternodes: dev %d paid %d miner %d of %d", n, d, tot, pow, r)
		}
	}
}

// re2 security H-2: Reference cannot carry separators, and lines of a block
// that share an OrderID must share the receiver.
func TestRE2_OrderFieldsStrict(t *testing.T) {
	for _, r := range []string{"a\x7fb", "a b", "a$b", "a(b", "a)b", "a:b", "", strings.Repeat("x", 65), "é"} {
		if types.ValidReference(r) {
			t.Fatalf("reference %q accepted", r)
		}
	}
	b := newBed(t, 1)
	a := b.nodes[0]
	b.fastForward(10, []string{a.Wallet.At(0).Hash}, []int64{1000000000000})
	w := a.Wallet.At(0)
	r1, _ := addr(t)
	r2, _ := addr(t)
	ts := b.slot()
	o1, k := signedOrder(t, w, "TRFR", r1.Hash, "ref", 10, 1000000, ts-100)
	w2, _ := addr(t)
	_ = w2
	o2, _ := signedOrder(t, w, "TRFR", r2.Hash, "ref", 20, 1000000, ts-100)
	o1.OrderLines, o2.OrderLines = 2, 2
	o1.TrxLine, o2.TrxLine = 1, 2
	o1.OrderID = "ORsame"
	o2.OrderID = "ORsame"
	if err := checkOrderGroups([]types.Order{o1, o2}); err == nil {
		t.Fatal("one order paying two receivers accepted")
	}
	_ = k
}

// A real chain from genesis across block 8425 (the end of the empty proof of
// stake tail rules), built block by block, synchronised by a second node
// through the archive path, restarted, and replayed from the blocks with every
// state root checked. fsync is off for the chain files (test-only store
// option); nothing else is relaxed.
func TestRE2_ChainAcrossBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("long")
	}
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	const target = consensus.PoSBlockStart + 3
	b := newBed(t, 1)
	a := b.nodes[0]
	dest := addrStr(t)
	pays := int64(0)
	for a.MyLastBlock() < target {
		if a.MyLastBlock()%2000 == 7 {
			pays++
			b.pay(a, dest, 1000000000, 1000000, a)
		}
		b.build(a)
	}
	f, _ := New(t.TempDir()+"/NOSODATA", nil)
	f.SetClock(func() int64 { return *b.now })
	if err := f.SetProposers(a.Proposers()); err != nil {
		t.Fatal(err)
	}
	pull(t, f, a)
	sameState(t, a, f)
	g, err := New(f.Lay.Root, nil)
	if err != nil || g.MyLastBlock() != target {
		t.Fatalf("restart: %v", err)
	}
	g.SetClock(func() int64 { return *b.now })
	h := g.Summary.Hash()
	if err := g.RebuildSummary(); err != nil || g.Summary.Hash() != h {
		t.Fatalf("replay from genesis: %v", err)
	}
	if g.Summary.BalanceIndexed(dest) != pays*1000000000 {
		t.Fatalf("transfers lost: %d", g.Summary.BalanceIndexed(dest))
	}
}
