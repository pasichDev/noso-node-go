package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// A masternode that lives on 127.0.0.1 is listed on every node of a loopback
// network and paid, with real processes. The network was made by init-network,
// so its network file sets local_masternodes; nothing pretends to be a public
// address. Masternode payments begin at block 48010, which a clock running 200
// times faster than real time cannot reach in a test, so the chain up to block
// 48009 is built first, block by block through the normal builder, in this
// process (the same sealed blocks any node would make), and copied to the data
// directories of the other nodes before the daemons start. Everything from
// block 48010 on is made by the daemons.
func TestLoopbackMasternodeIsListedAndPaid(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 48009 blocks and runs four daemons")
	}
	storage.SetNoSyncForTests(true)
	defer storage.SetNoSyncForTests(false)
	const pass = "correct horse battery"
	t.Setenv("NOSO_WALLET_PASSPHRASE", pass)
	root := t.TempDir()
	bin := filepath.Join(root, "nosod")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	base := freePorts(t, 4)
	netDir := filepath.Join(root, "net")
	init := exec.Command(bin, "init-network", "-dir", netDir, "-nodes", "4", "-proposers", "3",
		"-base-port", strconv.Itoa(base), "-rpc-base-port", strconv.Itoa(base+10), "-clock-scale", strconv.Itoa(netScale))
	init.Env = os.Environ()
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init-network: %v\n%s", err, out)
	}
	dirs := make([]string, 4)
	for i := range dirs {
		dirs[i] = filepath.Join(netDir, fmt.Sprintf("node%d", i+1))
	}
	if raw, _ := os.ReadFile(filepath.Join(dirs[0], "network.txt")); !containsLine(string(raw), "local_masternodes true") {
		t.Fatalf("a loopback network must allow local masternodes:\n%s", raw)
	}

	// Node 1 (a proposer) builds the chain up to 48009 and becomes the
	// masternode: its first address holds the stake, a second one signs.
	n1, err := node.NewWithConfig(dirs[0], node.Config{WalletPassphrase: []byte(pass)})
	if err != nil {
		t.Fatal(err)
	}
	var now int64
	n1.SetClock(func() int64 { return now })
	last := int64(consensus.MNBlockStart - 1)
	end := time.Now().Unix()/consensus.SecondsPerBlock*consensus.SecondsPerBlock - consensus.SecondsPerBlock
	for num := int64(1); num <= last; num++ {
		ts := end - consensus.SecondsPerBlock*(last-num) // slots may be skipped; the chain ends just before "now"
		now = ts + node.OutOfTurnGrace
		if r, err := n1.BuildNewBlock(num, ts, n1.MyLastBlockHash(), "", "x"); err != nil || r == nil {
			t.Fatalf("build %d: %v %v", num, r, err)
		}
	}
	signer, err := n1.Wallet.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	funds := n1.Wallet.At(0)
	if n1.Summary.BalanceIndexed(funds.Hash) < consensus.GetStackRequired(consensus.MNBlockStart) {
		t.Fatalf("the proposer holds %d, the stake is %d", n1.Summary.BalanceIndexed(funds.Hash), consensus.GetStackRequired(consensus.MNBlockStart))
	}
	n1.UpdateOptions(func(o *node.StorageOptions) {
		o.MNIP = "127.0.0.1"
		o.MNPort = strconv.Itoa(base)
		o.MNFunds = funds.Hash
		o.MNSign = signer.Hash
	})
	if err := n1.SaveOptions(); err != nil {
		t.Fatal(err)
	}

	// The other nodes start from the same chain: copy the chain files, never
	// the wallets or options.
	for _, d := range dirs[1:] {
		for _, f := range []string{"BLOCKS", "UNDO", "blchhead.nos", "sumary.psk", "gvts.psk", "psos.dat", "highwater.seq"} {
			if err := copyTree(filepath.Join(dirs[0], f), filepath.Join(d, f)); err != nil {
				t.Fatal(err)
			}
		}
	}

	var ps []*proc
	for i, d := range dirs {
		ps = append(ps, &proc{dir: d, port: base + i, rpc: base + 10 + i})
	}
	defer func() {
		for _, p := range ps {
			p.stop()
		}
	}()
	for _, p := range ps {
		p.start(t, bin)
	}
	deadline := time.Now().Add(240 * time.Second)
	for time.Now().Before(deadline) {
		if num, ok := paidMasternodeBlock(t, ps, funds.Hash); ok {
			t.Logf("block %d lists and pays %s on all four nodes", num, funds.Hash)
			return
		}
		time.Sleep(time.Second)
	}
	for i, p := range ps {
		if raw, err := os.ReadFile(p.dir + ".log"); err == nil {
			if len(raw) > 3000 {
				raw = raw[len(raw)-3000:]
			}
			t.Logf("--- node%d log tail:\n%s", i+1, raw)
		}
	}
	t.Fatal("the loopback masternode was not listed and paid on every node")
}

// paidMasternodeBlock looks for a block above the start of masternode payments
// that every node holds in the same form and that pays addr as a masternode.
func paidMasternodeBlock(t *testing.T, ps []*proc, addr string) (int64, bool) {
	t.Helper()
	min := int64(1 << 62)
	for _, p := range ps {
		n, _ := p.tip()
		if int64(n) < min {
			min = int64(n)
		}
	}
	for num := min; num >= consensus.MNBlockStart; num-- {
		var first []byte
		for k, p := range ps {
			raw, err := os.ReadFile(filepath.Join(p.dir, "BLOCKS", fmt.Sprintf("%d.blk", num)))
			if err != nil {
				return 0, false
			}
			if k == 0 {
				first = raw
			} else if string(raw) != string(first) {
				return 0, false
			}
		}
		blk, err := storage.DecodeBlock(first)
		if err != nil {
			return 0, false
		}
		for _, a := range blk.MNsAddrs {
			if a == addr && blk.MNsPay > 0 {
				return num, true
			}
		}
	}
	return 0, false
}

func containsLine(text, want string) bool {
	for _, l := range splitLines(text) {
		if l == want {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// copyTree copies a file or a directory tree.
func copyTree(src, dst string) error {
	fi, err := os.Stat(src)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }() // test cleanup
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close() // test cleanup
			return err
		}
		return out.Close()
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range ents {
		if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
