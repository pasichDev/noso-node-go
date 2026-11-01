package node

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// Crash injection: the n-th crash point of an operation panics, which stands in
// for a power loss. The tests reopen the directory the way a restart does.

type crashed struct{ at string }

func arm(n int) {
	c := 0
	storage.CrashHook = func(s string) {
		c++
		if c == n {
			storage.CrashHook = nil
			storage.Crashed = true
			panic(crashed{s})
		}
	}
}

func runCrash(f func()) (at string) {
	defer func() {
		r := recover()
		storage.CrashHook = nil
		storage.Crashed = false
		if r == nil {
			return
		}
		if c, ok := r.(crashed); ok {
			at = c.at
			return
		}
		panic(r)
	}()
	f()
	return ""
}

func cpdir(t *testing.T, src string) string {
	d := filepath.Join(t.TempDir(), "NOSODATA")
	if out, err := exec.Command("cp", "-R", src, d).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	return d
}

func openAt(t *testing.T, dir string) (*Node, error) {
	_ = storage.RecoverDataDir(dir)
	return New(dir, nil)
}

// consistent: the node is on one consistent chain.
func consistent(n *Node) error {
	last := n.MyLastBlock()
	if n.Corrupt() {
		return fmt.Errorf("corrupt")
	}
	if int64(n.Headers.Height()) != last {
		return fmt.Errorf("headers %d tip %d", n.Headers.Height(), last)
	}
	if n.Summary.LastOp() != last {
		return fmt.Errorf("lastop %d tip %d", n.Summary.LastOp(), last)
	}
	if last >= 1 {
		blk, err := n.Blocks.Read(last)
		if err != nil {
			return err
		}
		if r, _, _ := parseSolution(blk.Header.Solution); r != n.stateRoot() {
			return fmt.Errorf("root")
		}
	}
	all := n.Headers.All()
	for i := int64(0); i <= last; i++ {
		if crypto.IDHashFile(n.Lay.BlockFile(i)) != all[i].BlockHash || int64(all[i].Block) != i {
			return fmt.Errorf("header record %d", i)
		}
	}
	if n.DB != nil && int64(n.DB.LastBlock()) > last {
		return fmt.Errorf("blocks database ahead of the chain")
	}
	return nil
}

// undoCheck: every UNDO/N of n holds the state before block N of the reference.
func undoCheck(n, ref *Node) error {
	ents, _ := os.ReadDir(filepath.Join(n.Lay.Root, "UNDO"))
	for _, e := range ents {
		v, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil || v > n.MyLastBlock() || v < 1 {
			continue
		}
		a, _ := os.ReadFile(filepath.Join(n.undoDir(e.Name()), "sumary.psk"))
		b, err := os.ReadFile(filepath.Join(ref.undoDir(e.Name()), "sumary.psk"))
		if err != nil {
			continue
		}
		if string(a) != string(b) {
			return fmt.Errorf("stale UNDO/%d", v)
		}
	}
	return nil
}

// final-consensus 2: a crash while genesis was written forked the node for good.
// At every crash point of the first start, the next start ends with the genesis
// every honest node has, or with an error.
func TestFinal_CrashDuringGenesisEveryPoint(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	ref := newBed(t, 1).nodes[0]
	same := func(n *Node) error {
		if n.MyLastBlock() != 0 || n.Headers.Height() != 0 || n.Summary.Hash() != ref.Summary.Hash() ||
			n.Headers.Hash() != ref.Headers.Hash() || n.MyLastBlockHash() != ref.MyLastBlockHash() ||
			n.GVTs.Hash() != ref.GVTs.Hash() || n.PSOs.FileHash() != ref.PSOs.FileHash() || n.stateRoot() != ref.stateRoot() {
			return fmt.Errorf("genesis differs: admin %d (want %d), genesis account %d, headers %d",
				n.Summary.BalanceIndexed("N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"), ref.Summary.BalanceIndexed("N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"),
				n.Summary.BalanceIndexed(storage.GenesisAddress), n.Headers.Height())
		}
		return consistent(n)
	}
	points, hardErrors := 0, 0
	for c := 1; c < 400; c++ {
		d := filepath.Join(t.TempDir(), "NOSODATA")
		arm(c)
		at := runCrash(func() { _, _ = New(d, nil) })
		if at == "" {
			points = c - 1
			break
		}
		n, err := openAt(t, d)
		if err != nil {
			hardErrors++ // a hard error is an allowed outcome, but must not be the usual one
			continue
		}
		if err := same(n); err != nil {
			t.Errorf("crash %d at %s: %v", c, at, err)
			continue
		}
	}
	if points < 40 {
		t.Fatalf("only %d crash points: the hooks are not reached", points)
	}
	if hardErrors*2 > points {
		t.Fatalf("%d of %d crash points ended in a hard error: the test would pass without proving a recovery", hardErrors, points)
	}
	t.Logf("%d crash points, %d ended in a hard error", points, hardErrors)
}

// A second crash during the repair of the first.
func TestFinal_DoubleCrashDuringGenesis(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	ref := newBed(t, 1).nodes[0]
	var firsts []int
	for c := 1; c < 400; c += 5 {
		firsts = append(firsts, c)
	}
	for _, c1 := range firsts {
		d := filepath.Join(t.TempDir(), "NOSODATA")
		arm(c1)
		if runCrash(func() { _, _ = New(d, nil) }) == "" {
			break
		}
		for c2 := 1; c2 < 400; c2 += 4 {
			d2 := cpdir(t, d)
			_ = storage.RecoverDataDir(d2)
			arm(c2)
			if runCrash(func() { _, _ = New(d2, nil) }) == "" {
				break
			}
			n, err := openAt(t, d2)
			if err != nil {
				continue
			}
			if n.Summary.Hash() != ref.Summary.Hash() || n.GVTs.Hash() != ref.GVTs.Hash() || n.stateRoot() != ref.stateRoot() || consistent(n) != nil {
				t.Fatalf("crashes %d then %d: genesis differs or inconsistent", c1, c2)
			}
		}
	}
}

// final-consensus 6: a crash between the end of the journal and the promotion of
// the undo data left a stale UNDO/N, and a later heavier branch was refused.
// At every crash point of a reorganisation, the node recovers to a consistent
// chain, the undo data is the data of the chain it ends on, and delivering the
// blocks again converges.
func TestFinal_CrashDuringReorgEveryPoint(t *testing.T) {
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	b := newBed(t, 2)
	a, s := b.nodes[0], b.nodes[1]
	for i := 0; i < 3; i++ {
		b.build(a)
	}
	pull(t, s, a)
	ts := b.slot()
	for SlotOf(ts)%2 != 1 {
		ts = b.slot()
	}
	b.buildAt(s, ts) // Y1, in turn
	b.buildAt(a, ts) // X1, out of turn
	*b.now += 600 * 3
	b.buildAt(a, b.slot()) // X2
	base := cpdir(t, a.Lay.Root)
	t3 := b.slot()
	b.buildAt(s, t3)
	b.buildAt(s, b.slot())
	run := func(n *Node) {
		m := map[int64][]byte{}
		for i := int64(1); i <= s.MyLastBlock(); i++ {
			m[i] = readF(s.Lay.BlockFile(i))
		}
		_, _ = n.AcceptBlocks(m)
	}
	fails := map[string]int{}
	total := 0
	for c := 1; c < 400; c++ {
		d := cpdir(t, base)
		n, err := openAt(t, d)
		if err != nil {
			t.Fatal(err)
		}
		arm(c)
		at := runCrash(func() { run(n) })
		if at == "" {
			total = c
			break
		}
		n2, err := openAt(t, d)
		if err != nil {
			fails["reopen: "+err.Error()]++
			continue
		}
		if err := consistent(n2); err != nil {
			fails[fmt.Sprintf("%s: after recovery: %v", at, err)]++
			continue
		}
		run(n2)
		if err := consistent(n2); err != nil {
			fails[fmt.Sprintf("%s: after re-delivery: %v", at, err)]++
		}
		if n2.MyLastBlockHash() != s.MyLastBlockHash() || n2.Summary.Hash() != s.Summary.Hash() || n2.GVTs.Hash() != s.GVTs.Hash() {
			fails[fmt.Sprintf("%s: not converged", at)]++
		}
		if err := undoCheck(n2, s); err != nil {
			fails[fmt.Sprintf("%s: %v", at, err)]++
		}
	}
	var ks []string
	for k := range fails {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		t.Errorf("%s (x%d)", k, fails[k])
	}
	t.Logf("%d crash points", total)
}
