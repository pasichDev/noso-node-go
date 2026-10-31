package node

import (
	"os"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// fastForward is the synthetic fast path of the boundary tests: it makes
// every node of the bed believe the chain stands at `height` without building
// the blocks in between. It writes one header-only block file at that height,
// credits the given accounts in the summary (the same on every node, in the
// same order) and moves the clock to the following slot. Everything after it
// is real: built, sealed, validated and applied. Real chains reach the
// boundaries by the same rules; this only skips the wait. (Building 88500
// real blocks is not feasible in a test: the headers file is rehashed per
// block.)
func (b *bed) fastForward(height int64, fund []string, amounts []int64) {
	b.t.Helper()
	timeEnd := int64(consensus.GenesysTimeStamp) + 600*height
	for _, n := range b.nodes {
		h := types.BlockHeader{Number: height, TimeStart: timeEnd - 599, TimeEnd: timeEnd, TimeTotal: 599,
			LastBlockHash: "synthetic", AccountMiner: consensus.ProjectFunds, Reward: consensus.GetBlockReward(height)}
		blk := &storage.Block{Header: h}
		if err := os.WriteFile(n.Lay.BlockFile(height), blk.Encode(), 0o644); err != nil {
			b.t.Fatal(err)
		}
		n.Summary.ResetBlockRecords()
		for i, a := range fund {
			n.Summary.CreditTo(a, amounts[i], height)
		}
		n.Summary.CreditTo(storage.GenesisAddress, 0, height)
		if err := n.Summary.UpdateChanges(); err != nil {
			b.t.Fatal(err)
		}
		n.Summary.SetLastOp(height)
		n.SetMyLastBlock(height)
		n.UpdateMyData()
		n.Summary.SetHash()
		n.Headers.Add(height, n.MyLastBlockHash(), n.Summary.Hash())
		n.PSOs.Save(int(height))
		n.noteTip(height)
	}
	*b.now = timeEnd + 100
}

func addr(t *testing.T) (types.Wallet, string) {
	kp := crypto.GenerateKeyPair()
	return types.Wallet{Hash: crypto.GetAddressFromPublicKey(kp.PublicKey, 0), PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}, kp.PublicKey
}
