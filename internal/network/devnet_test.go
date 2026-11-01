package network

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// A small network of real engines on 127.0.0.1, one listener port each, real
// TCP and the real Start loops. Only the chain clock runs faster than the
// wall clock, as the same function of wall time for every node. Nothing here
// ever dials anything but loopback: every node gets an explicit seed list of
// its siblings.

type devnet struct {
	t     *testing.T
	nodes []*node.Node
	eng   []*Engine
	ports []int
	speed int64
	base  int64
	wall0 time.Time
}

// virtual returns the shared chain clock.
func (d *devnet) virtual() int64 {
	return d.base + int64(time.Since(d.wall0).Seconds()*float64(d.speed))
}

// newDevnet creates n nodes, the first `proposers` of which hold the proposer
// keys. Listeners are opened on free loopback ports before anything starts.
func newDevnet(t *testing.T, n, proposers int, speed int64) *devnet {
	return newDevnetWith(t, n, proposers, speed, nil)
}

// newDevnetWith gives every node the network file cfg (nil: no file, the
// default network).
func newDevnetWith(t *testing.T, n, proposers int, speed int64, cfg *node.NetworkConfig) *devnet {
	t.Helper()
	d := &devnet{t: t, speed: speed, wall0: time.Now()}
	d.base = time.Now().Unix()/consensus.SecondsPerBlock*consensus.SecondsPerBlock + consensus.SecondsPerBlock + 15
	for i := 0; i < n; i++ {
		dir := filepath.Join(t.TempDir(), "NOSODATA")
		if cfg != nil {
			if err := node.WriteNetworkConfig(dir, *cfg); err != nil {
				t.Fatal(err)
			}
		}
		nd, err := node.New(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		nd.SetClock(d.virtual)
		d.nodes = append(d.nodes, nd)
	}
	var keys []string
	for i := 0; i < proposers; i++ {
		keys = append(keys, d.nodes[i].Wallet.At(0).PublicKey)
	}
	for i, nd := range d.nodes {
		if err := nd.SetProposers(keys); err != nil {
			t.Fatal(err)
		}
		nd.UpdateOptions(func(o *node.StorageOptions) {
			o.AutoServer = true
			o.BuildBlocks = i < proposers
			o.MNIP = "127.0.0.1"
			o.MNSign = nd.Wallet.At(0).Hash
		})
		e := NewEngine(nd)
		idx := i
		nd.Log = func(ch, m string) {
			if os.Getenv("DEVNET_LOG") != "" && ch != "console" || strings.Contains(m, "Updated") {
				fmt.Printf("%s n%d [%s] %s\n", time.Now().Format("05.000"), idx, ch, m)
			}
		}
		e.Log = nd.Log
		e.BindAddr = "127.0.0.1" // the test network never leaves loopback
		e.Wall = func() int64 { return time.Now().Unix() }
		d.eng = append(d.eng, e)
	}
	for range d.eng {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		d.ports = append(d.ports, ln.Addr().(*net.TCPAddr).Port)
		_ = ln.Close()
	}
	for i, nd := range d.nodes {
		seeds := ""
		for _, p := range d.ports { // the same list on every node, itself included, as init-network writes it
			seeds += fmt.Sprintf("127.0.0.1;%d:", p)
		}
		nd.CFG.Save("NORMAL " + seeds + " null: null: null: NpryectdevepmentfundsGE:")
		nd.UpdateOptions(func(o *node.StorageOptions) { o.MNPort = fmt.Sprint(d.ports[i]) })
	}
	return d
}

func (d *devnet) start(idx ...int) {
	d.t.Helper()
	for _, i := range idx {
		d.eng[i].Start()
	}
}

func (d *devnet) stopAll() {
	for _, e := range d.eng {
		e.Stop()
	}
}

// converged reports whether every given node holds the same tip at least at
// height min.
func (d *devnet) converged(min int64, idx ...int) bool {
	var tip string
	for k, i := range idx {
		nd := d.nodes[i]
		if nd.MyLastBlock() < min {
			return false
		}
		if k == 0 {
			tip = nd.MyLastBlockHash()
		} else if nd.MyLastBlockHash() != tip || nd.MyLastBlock() != d.nodes[idx[0]].MyLastBlock() {
			return false
		}
	}
	return true
}

func (d *devnet) waitConverged(what string, min int64, within time.Duration, idx ...int) {
	d.t.Helper()
	deadline := time.Now().Add(within)
	next := time.Now()
	for time.Now().Before(deadline) {
		if d.converged(min, idx...) {
			return
		}
		if time.Now().After(next) {
			next = next.Add(10 * time.Second)
			d.t.Log(d.status())
		}
		time.Sleep(200 * time.Millisecond)
	}
	d.t.Fatalf("%s: no convergence at >= %d within %v: %s", what, min, within, d.status())
}

func (d *devnet) status() string {
	var st []string
	for i, nd := range d.nodes {
		var ps []string
		for k := 1; k <= MaxConnections; k++ {
			if p := d.eng[i].Peer(k); p.Tipo != "" {
				ps = append(ps, fmt.Sprintf("%s%d", p.Tipo, p.ListeningPort-d.ports[0]))
			}
		}
		st = append(st, fmt.Sprintf("n%d h=%d st=%d peers=%v tip=%.6s", i, nd.MyLastBlock(), nd.ConStatus(),
			ps, nd.MyLastBlockHash()))
	}
	return strings.Join(st, " | ")
}

// TestDevnetBlocksSpreadWithoutSeedVotes is the 4-node simulation of the
// review (re2 finding C1/H-5): three proposers, one follower, seeds are the
// sibling nodes, nobody is forced into serving. Every block built by the node
// whose turn it is must reach all the others and the chain must keep
// advancing.
func TestDevnetBlocksSpreadWithoutSeedVotes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a few block periods on a fast chain clock")
	}
	d := newDevnet(t, 4, 3, 100)
	defer d.stopAll()
	d.start(0, 1, 2, 3)
	d.waitConverged("4 nodes, 3 proposers", 6, 90*time.Second, 0, 1, 2, 3)
}

// restart stops node i's engine and starts a new one over the same node, the
// way a process restart reopens the same data directory.
func (d *devnet) restart(i int) {
	d.t.Helper()
	d.eng[i].Stop()
	nd := d.nodes[i]
	e := NewEngine(nd)
	e.Wall = func() int64 { return time.Now().Unix() }
	e.BindAddr = "127.0.0.1"
	e.Log = nd.Log
	d.eng[i] = e
	e.Start()
}

// cut separates the nodes in a from the nodes in b (both directions).
func (d *devnet) cut(a, b []int) {
	for _, i := range a {
		for _, j := range b {
			d.eng[i].DenyPeer(fmt.Sprintf("127.0.0.1:%d", d.ports[j]))
			d.eng[j].DenyPeer(fmt.Sprintf("127.0.0.1:%d", d.ports[i]))
		}
	}
}

func (d *devnet) heal() {
	for _, e := range d.eng {
		e.AllowPeer("all")
	}
}

// waitDifferent waits until the two groups hold different tips.
func (d *devnet) waitFork(a, b int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if d.nodes[a].MyLastBlock() >= 1 && d.nodes[b].MyLastBlock() >= 1 &&
			d.nodes[a].MyLastBlockHash() != d.nodes[b].MyLastBlockHash() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// TestDevnetOrderRestartAndPartitionHeal is the in-process version of the
// whole story: an order placed on one node reaches the chain of all of them,
// a restarted node catches up, two halves that each keep building diverge and
// then converge on one chain after the partition heals.
func TestDevnetOrderRestartAndPartitionHeal(t *testing.T) {
	if testing.Short() {
		t.Skip("runs several minutes of chain time")
	}
	d := newDevnet(t, 4, 3, 150)
	defer d.stopAll()
	d.start(0, 1, 2, 3)
	d.waitConverged("start", 3, 90*time.Second, 0, 1, 2, 3)

	// 1. an order placed on the observer reaches every node's chain
	// (proposers earn the masternode share of each block they build)
	var from int
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 3; i++ {
			if d.eng[i].WalletBalance() > 1000000 {
				from = i
			}
		}
		if d.eng[from].WalletBalance() > 1000000 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	dest := "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"
	var said []string
	var res string
	for try := 0; try < 40; try++ { // state 2 for a moment while a new block is on its way
		res = d.eng[from].SendFunds("sendto "+dest+" 100000 test", func(s string) { said = append(said, s) }, 0)
		if res != "ERROR 20" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if strings.HasPrefix(res, "ERROR") || res == "" {
		t.Fatalf("order not accepted: %q %v (balance %d)", res, said, d.eng[from].WalletBalance())
	}
	until := time.Now().Add(60 * time.Second)
	for time.Now().Before(until) {
		ok := true
		for _, nd := range d.nodes {
			ok = ok && nd.Summary.BalanceIndexed(dest) >= 100000
		}
		if ok {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	for i, nd := range d.nodes {
		if nd.Summary.BalanceIndexed(dest) < 100000 {
			t.Fatalf("node %d never saw the payment: %s", i, d.status())
		}
	}

	// 2. a restarted proposer catches up
	d.restart(1)
	h := d.nodes[0].MyLastBlock()
	d.waitConverged("after restart", h+2, 90*time.Second, 0, 1, 2, 3)

	// 3. partition {0,1} | {2,3}: both halves keep building, then heal
	d.cut([]int{0, 1}, []int{2, 3})
	if !d.waitFork(0, 2, 90*time.Second) {
		t.Fatalf("the halves never diverged: %s", d.status())
	}
	time.Sleep(10 * time.Second)
	d.heal()
	h = d.nodes[0].MyLastBlock()
	d.waitConverged("after the partition healed", h, 120*time.Second, 0, 1, 2, 3)
}

// TestDevnetDeepForkHeals cuts the network so that the losing half builds
// more blocks than the reorganisation depth probed at first (20) while the
// winning half builds more; after the heal the losers fetch the winning
// branch in windows (a not-yet-heavier branch is staged and continued) and
// everybody ends on one chain.
func TestDevnetDeepForkHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("runs several minutes of chain time")
	}
	d := newDevnet(t, 4, 3, 400)
	defer d.stopAll()
	d.start(0, 1, 2, 3)
	d.waitConverged("start", 3, 90*time.Second, 0, 1, 2, 3)
	fork := d.nodes[0].MyLastBlock()
	d.cut([]int{0, 1}, []int{2, 3})
	// the lone proposer (node 2) must pile up more than 20 blocks of its own
	deadline := time.Now().Add(240 * time.Second)
	for time.Now().Before(deadline) && d.nodes[2].MyLastBlock() < fork+24 {
		time.Sleep(500 * time.Millisecond)
	}
	if d.nodes[2].MyLastBlock() < fork+24 {
		t.Fatalf("the minority half did not get 24 blocks deep: %s", d.status())
	}
	if d.nodes[0].MyLastBlockHash() == d.nodes[2].MyLastBlockHash() {
		t.Fatal("no fork")
	}
	d.heal()
	h := d.nodes[0].MyLastBlock()
	d.waitConverged("after the deep fork healed", h, 180*time.Second, 0, 1, 2, 3)
}
