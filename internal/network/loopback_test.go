package network

import (
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

type clock struct{ v atomic.Int64 }

func (c *clock) now() int64 { return c.v.Load() }

func mkNode(t *testing.T, c *clock) *node.Node {
	n, err := node.New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetClock(c.now)
	return n
}

// drive ticks the engine until done() or the deadline.
func drive(t *testing.T, what string, d time.Duration, engines []*Engine, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, e := range engines {
			e.Tick()
		}
		if done() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", what)
}

// Two Go nodes on loopback: B starts empty, learns the consensus from A's
// NODESTATUS, downloads headers, blocks and the summary through the same
// wire messages a Pascal node would use, and ends in state 3 with identical
// files.
func TestLoopbackSync(t *testing.T) {
	var clkA, clkB clock
	base := int64(consensus.GenesysTimeStamp) + 600*10
	clkA.v.Store(base)
	clkB.v.Store(base)
	a, b := mkNode(t, &clkA), mkNode(t, &clkB)
	// Blocks are sealed by an authorised proposer: A's default key is the
	// only proposer on both nodes.
	for _, n := range []*node.Node{a, b} {
		if err := n.SetProposers([]string{a.Wallet.At(0).PublicKey}); err != nil {
			t.Fatal(err)
		}
	}
	// A builds three blocks on its own, one per 10 minutes.
	miner := a.Wallet.At(0).Hash
	dest := "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"
	for i := int64(1); i <= 3; i++ {
		clkA.v.Add(600)
		ts := clkA.now()
		if i == 2 {
			o, err := a.SendFundsFromAddress(miner, dest, 1000000000, 1000000, "ref", strconv.FormatInt(ts-500, 10), 1)
			if err != nil {
				t.Fatal(err)
			}
			o.OrderID = "ORtest" + strconv.Itoa(int(i))
			if !a.AddPool(o) {
				t.Fatal("pool")
			}
		}
		if _, err := a.BuildNewBlock(i, ts, a.MyLastBlockHash(), miner, BuildSolution); err != nil {
			t.Fatal(err)
		}
	}
	// Fix both clocks 100 s into the same period (not near a block boundary).
	now := (clkA.now()/600)*600 + 100
	clkA.v.Store(now)
	clkB.v.Store(now)

	ea, eb := NewEngine(a), NewEngine(b)
	ea.MinPeers, eb.MinPeers = 1, 1
	if err := ea.StartServer(0); err != nil {
		t.Fatal(err)
	}
	defer ea.Stop()
	defer eb.Stop()
	_, port, _ := splitHostPort(ea.ServerAddr())
	seeds := "127.0.0.1;" + port + ":"
	a.CFG.Save("NORMAL " + seeds + " ts2.aco.net: null: null: NpryectdevepmentfundsGE:")
	b.CFG.Save("NORMAL " + seeds + " ts2.aco.net: null: null: NpryectdevepmentfundsGE:")
	a.SetConStatus(3)
	ea.SetNodesArray(a.CFG.Param(1))
	eb.SetNodesArray(b.CFG.Param(1))
	eb.forceCompleteHeadersDownload = true

	if cons := ea.CalculateConsensus(); len(cons) < 18 || cons[2] != "3" {
		t.Fatalf("A consensus %v", cons)
	}
	if sl := eb.ConnectClient("127.0.0.1", port); sl == 0 {
		t.Fatal("B could not connect")
	}
	eb.CalculateConsensus()

	drive(t, "B reaches status 3", 20*time.Second, []*Engine{ea, eb}, func() bool {
		if b.ConStatus() < 3 {
			eb.lastConsensusTime = 0
			eb.CalculateConsensus()
		}
		return b.ConStatus() == 3
	})

	if b.MyLastBlock() != 3 || b.MyLastBlockHash() != a.MyLastBlockHash() {
		t.Fatalf("blocks differ: %d %s vs %s", b.MyLastBlock(), b.MyLastBlockHash(), a.MyLastBlockHash())
	}
	if b.Summary.Hash() != a.Summary.Hash() {
		t.Fatal("summary hash differs")
	}
	if b.Headers.Hash() != a.Headers.Hash() {
		t.Fatal("headers hash differs")
	}
	if b.Summary.BalanceIndexed(dest) != a.Summary.BalanceIndexed(dest) || a.Summary.BalanceIndexed(dest) < 1000000000 {
		t.Fatal("balances differ")
	}
	pa := ea.Peer(1)
	if pa.Tipo != "CLI" || !pa.Autentic || pa.Version != "0.4.4zzz" {
		t.Fatalf("A's view of B: %+v", pa)
	}
}

func TestIncomingChecks(t *testing.T) {
	var clk clock
	clk.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, &clk)
	e := NewEngine(n)
	n.SetConStatus(3)
	if err := e.StartServer(0); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	_, port, _ := splitHostPort(e.ServerAddr())
	ask := func(line string) string {
		return e.RequestLine("127.0.0.1", mustAtoi(port), line)
	}
	if got := ask("NSLTIME"); got != n.UTCTimeStr() {
		t.Fatalf("NSLTIME %q", got)
	}
	if got := ask("GETMIIP"); got != "127.0.0.1" {
		t.Fatalf("GETMIIP %q", got)
	}
	if got := ask("NODESTATUS"); len(got) < 40 || got[:11] != "NODESTATUS " {
		t.Fatalf("NODESTATUS %q", got)
	}
	if got := ask("NSLCFG"); got != n.CFG.DataStr() {
		t.Fatal("NSLCFG")
	}
	if got := ask("NSLPEND"); got != "" {
		t.Fatalf("NSLPEND %q", got)
	}
	if got := ask("MNVER"); got != "False" {
		t.Fatalf("MNVER %q", got)
	}
	if got := ask("GARBAGE LINE"); got != "WRONG_PROTOCOL" {
		t.Fatalf("garbage %q", got)
	}
	// FIX(M6): loopback is never banned (every local node shares it), a stranger is.
	if got := ask("NSLTIME"); got != n.UTCTimeStr() {
		t.Fatalf("loopback was banned after one bad greeting: %q", got)
	}
	e.UpdateBotData("203.0.113.7")
	if !e.BotExists("203.0.113.7") {
		t.Fatal("a remote address that broke the protocol is not registered")
	}
	e.UpdateBotData("127.0.0.1")
	if e.BotExists("127.0.0.1") {
		t.Fatal("loopback registered as a bot")
	}
	_ = storage.FundsAddress
}
