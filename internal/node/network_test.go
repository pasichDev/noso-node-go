package node

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func TestParseNetworkConfigIsStrict(t *testing.T) {
	good := "chain_id abcdefgh-1\nlocal_masternodes true\n"
	if _, err := ParseNetworkConfig(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", "chain_id abcdefgh-1\n", "local_masternodes true\n",
		good + "extra 1\n", good + "chain_id abcdefgh-2\n",
		"chain_id short\nlocal_masternodes true\n",
		"chain_id abcdefgh-1\nlocal_masternodes maybe\n",
		"chain_id has space x\nlocal_masternodes true\n",
	} {
		if _, err := ParseNetworkConfig(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// comments and spacing do not change the digest, values do
	a, _ := ParseNetworkConfig("# c\n" + good)
	b, _ := ParseNetworkConfig("chain_id   abcdefgh-1\nlocal_masternodes   true\n\n")
	c, _ := ParseNetworkConfig("chain_id abcdefgh-1\nlocal_masternodes false\n")
	if a.Digest() != b.Digest() || a.Digest() == c.Digest() {
		t.Fatal("digest must cover the values only")
	}
}

// networkBed is a bed whose nodes each have the given network file.
func networkBed(t *testing.T, cfgs ...NetworkConfig) *bed {
	now := new(int64)
	*now = int64(consensus.GenesysTimeStamp) + 600
	b := &bed{t: t, now: now}
	var keys []string
	for _, c := range cfgs {
		dir := filepath.Join(t.TempDir(), "NOSODATA")
		if err := WriteNetworkConfig(dir, c); err != nil {
			t.Fatal(err)
		}
		n, err := New(dir, nil)
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

// F-18: an order signed on one network is refused on another, even when the
// key and the time window are the same.
func TestOrderSignedOnAnotherNetworkIsRefused(t *testing.T) {
	ca, _ := NewNetworkConfig(true)
	cb, _ := NewNetworkConfig(true)
	b := networkBed(t, ca, cb)
	a, o := b.nodes[0], b.nodes[1]
	b.build(a)
	pull(t, o, a)
	w := a.Wallet.At(0)
	line, err := a.SendFundsFromAddress(w.Hash, o.Wallet.At(0).Hash, 1000000, 1000000, "ref", strconv.FormatInt(*b.now-100, 10), 1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.SealOrder([]types.Order{line})
	if err != nil {
		t.Fatal(err)
	}
	if c := VerifyOrder(a.ChainID(), sealed[0]); c != 0 {
		t.Fatalf("own network refused its order: %d", c)
	}
	if c := VerifyOrder(o.ChainID(), sealed[0]); c == 0 {
		t.Fatal("an order signed on another network verified")
	}
	if !a.AddPoolGroup(sealed) {
		t.Fatal("setup")
	}
	wire := PTCHeader(o) + "ORDER 1 $" + types.StringFromOrder(sealed[0])
	if r := o.PTCOrder(wire); !strings.HasPrefix(r, "ERROR") && r != "" {
		t.Fatalf("other network admitted the order: %q", r)
	}
	if o.PendingCount() != 0 {
		t.Fatal("order in the pool of the other network")
	}
}

// Nodes whose network files differ, even in one value, cannot share a chain:
// every block commits to the file.
func TestBlocksCommitToTheNetworkFile(t *testing.T) {
	ca, _ := NewNetworkConfig(true)
	same := ca
	diff := ca
	diff.LocalMasternodes = false
	b := networkBed(t, ca, same, diff)
	a, ok, bad := b.nodes[0], b.nodes[1], b.nodes[2]
	b.build(a)
	z, err := a.ZipBlocks(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.StageBlocks(z); err != nil || ok.MyLastBlock() != 1 {
		t.Fatalf("same file refused: %v", err)
	}
	if _, err := bad.StageBlocks(z); bad.MyLastBlock() != 0 {
		t.Fatalf("a node with another local_masternodes took the block (%v)", err)
	}
}
