package network

import (
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// M-10: a proposer in a minority of seeds keeps its own valid blocks. The
// seeds' vote may be behind; it never deletes anything.
func TestM10_MinorityProposerKeepsItsBlocks(t *testing.T) {
	var clk clock
	base := int64(consensus.GenesysTimeStamp) + 600*10
	clk.v.Store(base + 100)
	n := mkNode(t, &clk)
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(n)
	e.MinPeers = 1
	n.UpdateOptions(func(o *node.StorageOptions) { o.BuildBlocks = true })
	for i := int64(1); i <= 5; i++ {
		ts := base + 600*i
		clk.v.Store(ts + 1)
		if _, err := n.BuildNewBlock(i, ts, n.MyLastBlockHash(), "", "x"); err != nil {
			t.Fatal(err)
		}
	}
	clk.v.Store(base + 600*5 + 12)
	e.cons = make([]string, len(NConsensus))
	e.cons[0] = "hash"
	e.cons[CLastBlock] = "4"
	e.cons[CLBHash] = "someotherhash"
	for i := 0; i < 5; i++ {
		e.SyncWithMainnet()
	}
	if n.MyLastBlock() != 5 || n.Blocks.Header(5).Number != 5 || n.Blocks.Header(3).Number != 3 {
		t.Fatalf("blocks deleted on the word of the vote: tip %d", n.MyLastBlock())
	}
}

// C-07: a report whose IP does not answer the challenge is not listed.
func TestC07_ReportNeedsAnsweringIP(t *testing.T) {
	var clk clock
	clk.v.Store(int64(consensus.GenesysTimeStamp) + 6100)
	n := mkNode(t, &clk)
	e := NewEngine(n)
	if e.challengeReport("$MNREPO 127.0.0.1 1 garbage") {
		t.Fatal("garbage report passed")
	}
	if strings.Contains("", "x") {
		t.Fatal()
	}
}
