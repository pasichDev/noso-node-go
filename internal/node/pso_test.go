package node

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

const psoParams = "1:1615134000;2:1;3:1;4:500;5:2016;"

// psoOrder makes node n sign a NEWPSO order for its first address and puts it
// into the pool of every given node, as the network would.
func psoOrder(t *testing.T, n *Node, params string, nodes ...*Node) types.Order {
	t.Helper()
	o, err := n.NewPSOOrder(n.Wallet.At(0).Hash, 1, params)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range nodes {
		if c := m.PTCPSO("$" + types.StringFromOrder(o)); c != 0 {
			t.Fatalf("PSO order refused with code %d", c)
		}
	}
	return o
}

// Two nodes, one PSO: the order is mined, the PSO exists with the Pascal
// AddNewPSO values, both nodes have the same PSO file and the same state root,
// and a restart keeps it.
func TestPSOOrderMinedOnTwoNodesSameStateRoot(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, f, a)
	psoOrder(t, a, psoParams, a)
	b.build(a)
	pull(t, f, a)
	got := a.PSOs.All()
	if len(got) != 1 {
		t.Fatalf("PSOs after the block: %d", len(got))
	}
	p := got[0]
	if p.Mode != 1 || p.Owner != a.Wallet.At(0).Hash || p.Params != psoParams || p.Expire != 1+2016 || p.Hash == "" {
		t.Fatalf("PSO record: %+v", p)
	}
	sameState(t, a, f)
	if a.stateRoot() != f.stateRoot() || !reflect.DeepEqual(a.PSOs.All(), f.PSOs.All()) {
		t.Fatal("the nodes differ in the PSO state")
	}
	g, err := New(a.Lay.Root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.PSOs.All(), got) || g.stateRoot() != a.stateRoot() {
		t.Fatal("the PSO did not survive a restart")
	}
	if err := consistent(g); err != nil {
		t.Fatal(err)
	}
	// a replay from the blocks gives the same file
	if err := f.RebuildSummary(); err != nil || !reflect.DeepEqual(f.PSOs.All(), got) {
		t.Fatalf("replay: %v %v", err, f.PSOs.All())
	}
}

// A heavier branch without the order removes the PSO (the state goes back with
// the block), the order is back in the pool, and the next block makes the PSO
// again.
func TestPSOUndoneByReorgAndMinedAgain(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	bd := newBed(t, 3)
	a, p := bd.nodes[0], bd.nodes[1]
	bd.build(a)
	for _, n := range bd.nodes[1:] {
		pull(t, n, a)
	}
	o := psoOrder(t, a, psoParams, a)
	ts := bd.slot()
	for SlotOf(ts)%3 != 1 {
		ts = bd.slot()
	}
	bd.buildAt(a, ts) // out of turn, holds the order
	if len(a.PSOs.All()) != 1 {
		t.Fatal("setup: no PSO")
	}
	bd.buildAt(p, ts) // in turn, without it
	z, err := p.ZipBlocks(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.StageBlocks(z); err != nil {
		t.Fatal(err)
	}
	if a.MyLastBlockHash() != p.MyLastBlockHash() {
		t.Fatal("the heavier branch was not adopted")
	}
	if len(a.PSOs.All()) != 0 {
		t.Fatal("the PSO of the abandoned block is still there")
	}
	sameState(t, a, p)
	if !a.TranxAlreadyPending(o.TrfrID) {
		t.Fatal("the PSO order was not put back into the pool")
	}
	bd.build(a)
	if len(a.PSOs.All()) != 1 {
		t.Fatal("the order was not mined again")
	}
	pull(t, p, a)
	sameState(t, a, p)
}

// clearpsos removes the PSOs of its sender and nobody else's.
func TestClearPSOsRemovesOnlyTheSendersOwn(t *testing.T) {
	b := newBed(t, 2)
	a, f := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, f, a)
	b.build(f) // f earns a balance too
	pull(t, a, f)
	psoOrder(t, a, psoParams, a, f)
	psoOrder(t, f, "1:2;3:4;", a, f)
	b.build(a)
	pull(t, f, a)
	if len(a.PSOs.All()) != 2 {
		t.Fatalf("setup: %d PSOs", len(a.PSOs.All()))
	}
	clr, err := a.ClearPSOsOrder(a.Wallet.At(0).Hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, f} {
		if c := n.PTCPSO("$" + types.StringFromOrder(clr)); c != 0 {
			t.Fatalf("clear refused: %d", c)
		}
	}
	b.build(a)
	pull(t, f, a)
	rest := a.PSOs.All()
	if len(rest) != 1 || rest[0].Owner != f.Wallet.At(0).Hash {
		t.Fatalf("after clearpsos: %+v", rest)
	}
	sameState(t, a, f)
}

// Hard limits: the params are bounded in size and shape by the pool, the
// parser and the block validator; a validly signed order with bad params is
// refused with its block.
func TestPSOParamsLimits(t *testing.T) {
	good := []string{psoParams, "1:2", "a:b;c_d:e.f-g;", strings.Repeat("a:b;", 16)}
	bad := []string{"", "x", "1:2;3", ":1;", "1:2;;3:4", "toolonglabel:1;", "1:" + strings.Repeat("v", 65), "a b:1", "1:2 3:4",
		"1:$2", strings.Repeat("a:b;", 17), strings.Repeat("a:b;", 70), "1:2\n3:4", "é:1"}
	for _, s := range good {
		if !types.ValidPSOParams(s) {
			t.Errorf("refused %q", s)
		}
	}
	for _, s := range bad {
		if types.ValidPSOParams(s) {
			t.Errorf("accepted %q", s)
		}
	}
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	if _, err := a.NewPSOOrder(a.Wallet.At(0).Hash, 1, strings.Repeat("a:b;", 70)); err == nil {
		t.Error("oversize params signed")
	}
	if _, err := a.NewPSOOrder(a.Wallet.At(0).Hash, 0, psoParams); err == nil {
		t.Error("mode 0 signed")
	}
	// the block validator, not only the pool: a signed order with bad params
	o, err := a.NewPSOOrder(a.Wallet.At(0).Hash, 1, psoParams)
	if err != nil {
		t.Fatal(err)
	}
	prev := a.LastBlockData()
	ts := prev.TimeEnd + 600
	o.TimeStamp = prev.TimeEnd + 10
	check := func(mod func(*types.Order)) error {
		x := o
		mod(&x)
		SignOrder(a.ChainID(), &x, a.Wallet.At(0).PrivateKey)
		x.OrderID = SingleOrderID(x.TrfrID)
		return a.checkOrder(x, prev, ts)
	}
	if err := check(func(*types.Order) {}); err != nil {
		t.Fatalf("a good PSO order refused: %v", err)
	}
	for name, mod := range map[string]func(*types.Order){
		"params":  func(x *types.Order) { x.Params = "1:2 3:4" },
		"empty":   func(x *types.Order) { x.Params = "" },
		"fee":     func(x *types.Order) { x.AmmountFee++ },
		"amount":  func(x *types.Order) { x.AmmountTrf = 1 },
		"mode":    func(x *types.Order) { x.Reference = "007" },
		"receive": func(x *types.Order) { x.Receiver = a.Wallet.At(0).Hash },
		"clear+p": func(x *types.Order) { x.OrderType, x.Reference = PSOClear, "null" },
	} {
		if check(mod) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if consensus.MaxPSOPerBlock < 1 || consensus.MaxPSOPerOwner < 1 {
		t.Fatal("limits")
	}
}

// A signature covers the params: changing them after signing breaks the order.
func TestPSOParamsAreSigned(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	b.build(a)
	o, err := a.NewPSOOrder(a.Wallet.At(0).Hash, 1, psoParams)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyOrder(a.ChainID(), o) != 0 {
		t.Fatal("own order does not verify")
	}
	o.Params = "1:9;"
	if VerifyOrder(a.ChainID(), o) == 0 {
		t.Fatal("params changed after signing still verify")
	}
}

// PSOs expire at their block, deterministically, and are bounded per owner.
func TestPSOExpiryAndOwnerLimit(t *testing.T) {
	p := storage.OpenPSOs(t.TempDir() + "/psos.dat")
	p.AddNew(1, "o", 10, "1:2;")
	p.AddNew(1, "o", -1, "1:3;")
	if p.ClearExpiredPSOs(9) != 0 || p.ClearExpiredPSOs(10) != 1 || len(p.All()) != 1 {
		t.Fatal("expiry")
	}
	if p.CountOwner("o") != 1 || p.ClearOwner("x") != 0 || p.ClearOwner("o") != 1 || len(p.All()) != 0 {
		t.Fatal("owner helpers")
	}
}
