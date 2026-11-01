package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// reorgFixture builds two competing blocks 2 on the same block 1. Node a
// seals its block out of turn (after the grace period) and includes a payment;
// node b holds the turn and seals the same slot without it. b's block is the
// heavier one, so a must switch to it.
type reorgFixture struct {
	b      *bed
	a, p   *Node
	order  types.Order
	branch []byte // zip of b's blocks from the fork
}

func newReorgFixture(t *testing.T) *reorgFixture {
	t.Helper()
	storage.SetNoSyncForTests(true)
	t.Cleanup(func() { storage.SetNoSyncForTests(false) })
	bd := newBed(t, 3)
	a, p := bd.nodes[0], bd.nodes[1]
	bd.build(a)
	for _, n := range bd.nodes[1:] {
		pull(t, n, a)
	}
	w := a.Wallet.At(0)
	line, err := a.SendFundsFromAddress(w.Hash, p.Wallet.At(0).Hash, 1000000, 1000000, "ref", strconv.FormatInt(*bd.now-100, 10), 1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.SealOrder([]types.Order{line})
	if err != nil {
		t.Fatal(err)
	}
	o := sealed[0]
	if !a.AddPoolGroup(sealed) {
		t.Fatal("pool refused the order")
	}
	ts := bd.slot()
	for SlotOf(ts)%3 != 1 { // the slot of node p
		ts = bd.slot()
	}
	bd.buildAt(a, ts) // out of turn, with the payment
	bd.buildAt(p, ts) // in turn, without it
	if a.MyLastBlockHash() == p.MyLastBlockHash() {
		t.Fatal("setup: no fork")
	}
	if a.TranxAlreadyPending(o.TrfrID) {
		t.Fatal("setup: the order is still pending after it was mined")
	}
	z, err := p.ZipBlocks(2)
	if err != nil {
		t.Fatal(err)
	}
	return &reorgFixture{b: bd, a: a, p: p, order: o, branch: z}
}

// A heavier branch replaces our block: the payment of the abandoned block is
// valid on the new tip and goes back into the pool, once.
func TestReorgPutsValidOrdersBack(t *testing.T) {
	f := newReorgFixture(t)
	if _, err := f.a.StageBlocks(f.branch); err != nil {
		t.Fatal(err)
	}
	if f.a.MyLastBlockHash() != f.p.MyLastBlockHash() {
		t.Fatal("the heavier branch was not adopted")
	}
	if !f.a.TranxAlreadyPending(f.order.TrfrID) {
		t.Fatal("the order of the abandoned block was not put back into the pool")
	}
	if got := f.a.PendingCount(); got != 1 {
		t.Fatalf("pool holds %d lines, want 1", got)
	}
	// and it is mined again by the next block, not lost
	f.b.build(f.a)
	if f.a.PendingCount() != 0 {
		t.Fatal("order not mined from the pool")
	}
}

// An order the new branch already holds, or one whose signature window has
// closed, is not put back.
func TestReorgDoesNotReAddMinedOrExpiredOrders(t *testing.T) {
	f := newReorgFixture(t)
	// The same payment is in the heavier branch's pool: build it there too by
	// adding it to p's pool and mining a block on p, then reorganise a.
	if !f.p.AddPoolGroup([]types.Order{f.order}) {
		t.Fatal("pool refused order")
	}
	f.b.build(f.p)
	z, err := f.p.ZipBlocks(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.StageBlocks(z); err != nil {
		t.Fatal(err)
	}
	if f.a.MyLastBlockHash() != f.p.MyLastBlockHash() {
		t.Fatal("branch not adopted")
	}
	if f.a.PendingCount() != 0 {
		t.Fatalf("order that the new branch mined was put back (%d)", f.a.PendingCount())
	}
}

// A crash at any point of the reorganisation leaves one consistent chain, and
// no order twice. When the change had reached its commit point (the journal
// names the blocks) the order is back in the pool after the restart; when it
// had not, the chain is still the old one and the order is in its block.
func TestReorgCrashEveryPoint(t *testing.T) {
	f := newReorgFixture(t)
	points := 0
	for c := 1; c < 200; c++ {
		d := cpdir(t, f.a.Lay.Root)
		n, err := openAt(t, d)
		if err != nil {
			t.Fatal(err)
		}
		n.SetClock(func() int64 { return *f.b.now })
		arm(c)
		at := runCrash(func() { _, _ = n.StageBlocks(f.branch) })
		if at == "" {
			points = c - 1
			break
		}
		committed := false
		if raw, err := os.ReadFile(filepath.Join(d, journalFile)); err == nil {
			var j journal
			committed = jsonUnmarshal(raw, &j) == nil && j.Count > 0
		}
		m, err := openAt(t, d)
		if err != nil {
			t.Fatalf("crash %d (%s): restart: %v", c, at, err)
		}
		m.SetClock(func() int64 { return *f.b.now })
		if err := consistent(m); err != nil {
			t.Fatalf("crash %d (%s): %v", c, at, err)
		}
		pending := m.PendingCount()
		onNew := m.MyLastBlockHash() == f.p.MyLastBlockHash()
		switch {
		case pending > 1:
			t.Fatalf("crash %d (%s): order twice in the pool", c, at)
		case committed && (!onNew || pending != 1):
			t.Fatalf("crash %d (%s): committed change, tip new=%v, pool %d", c, at, onNew, pending)
		case !committed && !onNew && pending != 0:
			t.Fatalf("crash %d (%s): old chain still holds the order, but it is also pending", c, at)
		}
	}
	if points < 5 {
		t.Fatalf("only %d crash points were exercised", points)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
