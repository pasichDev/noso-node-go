package node

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func newTestNode(t *testing.T, now *int64) *Node {
	n, err := New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	n.SetClock(func() int64 { return *now })
	return n
}

func TestGenesisBlock(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 100
	n := newTestNode(t, &now)
	if n.MyLastBlock() != 0 {
		t.Fatal("last block")
	}
	h := n.LastBlockData()
	// mpblock.pas:150,376-384 for block 0.
	if h.Number != 0 || h.TimeStart != 1531896783 || h.TimeEnd != consensus.GenesysTimeStamp ||
		h.Reward != consensus.PremineAmount || h.AccountMiner != consensus.AdminHash ||
		h.LastBlockHash != "NOSO GENESYS BLOCK" || h.Solution != "" || h.Difficult != 60 ||
		h.TimeTotal != int32(consensus.GenesysTimeStamp-1531896783) {
		t.Fatalf("%+v", h)
	}
	// The premine lands on AdminHash (miner), the genesis account gets 0.
	if n.Summary.BalanceIndexed(consensus.AdminHash) != consensus.PremineAmount {
		t.Fatal("premine")
	}
	if n.Headers.Height() != 0 {
		t.Fatal("header record")
	}
	// 0.blk is exactly one header (no tails below block 8425).
	if got := len(mustRead(t, n.Lay.BlockFile(0))); got != types.HeaderSize {
		t.Fatalf("block 0 size %d", got)
	}
	// Deterministic: a second node produces a byte identical genesis file.
	now2 := int64(consensus.GenesysTimeStamp) + 5000
	n2 := newTestNode(t, &now2)
	if string(mustRead(t, n.Lay.BlockFile(0))) != string(mustRead(t, n2.Lay.BlockFile(0))) {
		t.Fatal("genesis block must be identical on every node")
	}
	if n.MyLastBlockHash() != n2.MyLastBlockHash() {
		t.Fatal("genesis hash")
	}
}

func TestBuildTransferBlockAndReplay(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	a := newTestNode(t, &now)
	miner := a.Wallet.At(0).Hash

	// Block 1: miner reward only.
	now += 600
	res, err := a.BuildNewBlock(1, now, a.MyLastBlockHash(), miner, "!!!!!!!!!100000000")
	if err != nil || res == nil {
		t.Fatal(err, res)
	}
	if a.Summary.BalanceIndexed(miner) != consensus.InitialReward {
		t.Fatalf("miner balance %d", a.Summary.BalanceIndexed(miner))
	}
	// Block 2 carries a transfer from the miner.
	dest := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	orderTime := now + 10
	now += 600
	o, err := a.SendFundsFromAddress(miner, dest, 1000000000, 1000000, "ref", itoa(orderTime), 1)
	if err != nil {
		t.Fatal(err)
	}
	o.OrderID = crypto.GetOrderHash("1" + itoa(orderTime) + o.TrfrID)
	if !a.AddPool(o) {
		t.Fatal("pool refused order")
	}
	res, err = a.BuildNewBlock(2, now, a.MyLastBlockHash(), miner, "!!!!!!!!!100000000")
	if err != nil || res == nil {
		t.Fatal(err, res)
	}
	if len(res.Block.Orders) != 1 || res.Block.Orders[0].Sender != miner {
		t.Fatalf("orders %+v", res.Block.Orders)
	}
	if a.Summary.BalanceIndexed(dest) != 1000000000 {
		t.Fatal("receiver credit")
	}
	// miner: 5e9 - (1e9 + 1e6 fee) + block2 reward 5e9 + fee 1e6
	if got, want := a.Summary.BalanceIndexed(miner), int64(5000000000-1000000000-1000000+5000000000+1000000); got != want {
		t.Fatalf("miner %d want %d", got, want)
	}
	if a.PendingCount() != 0 {
		t.Fatal("pool must be emptied")
	}

	// Replay the blocks on a second node through the summary-rebuild path.
	now2 := now
	b := newTestNode(t, &now2)
	for _, i := range []int64{1, 2} {
		raw := mustRead(t, a.Lay.BlockFile(i))
		writeFile(t, b.Lay.BlockFile(i), raw)
	}
	b.SetMyLastBlock(2)
	b.Summary.CreateNew(true) // block-0 premine on the genesis account
	b.Summary.CreateIndex()
	for i := int64(1); i <= 2; i++ {
		if err := b.AddBlockToSummary(i, true); err != nil {
			t.Fatal(err)
		}
	}
	if b.Summary.BalanceIndexed(miner) != a.Summary.BalanceIndexed(miner) ||
		b.Summary.BalanceIndexed(dest) != a.Summary.BalanceIndexed(dest) {
		t.Fatal("replayed balances differ")
	}
	// COMPAT: the replay path creates the AdminHash account touched every block.
	if b.Summary.AddressLastOP(consensus.AdminHash) != 2 {
		t.Fatal("admin account LastOP after replay")
	}
	if a.Summary.AddressLastOP(storageGenesis) != 2 {
		t.Fatal("genesis account LastOP after build")
	}
}

const storageGenesis = "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"

func TestPoSRangeDivisionByZero(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	n.SetMyLastBlock(8424)
	now += 600
	if _, err := n.BuildNewBlock(8425, now, "", "N1", "x"); err == nil || !strings.Contains(err.Error(), "division by zero") {
		t.Fatalf("expected EDivByZero reproduction, got %v", err)
	}
}

func TestOrderPoolOrdering(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	// ordered by timestamp, then OrderID, then TrxLine (nosonetwork.pas:294-321)
	last := n.LastBlockData().TimeStart
	mk := func(ts int64, id string, line int32, trf string) types.Order {
		return types.Order{TimeStamp: last + ts, OrderID: id, TrxLine: line, TrfrID: trf, OrderType: "TRFR"}
	}
	for _, o := range []types.Order{mk(5, "B", 1, "t1"), mk(5, "A", 1, "t2"), mk(3, "Z", 1, "t3"),
		mk(5, "A", 0, "t4"), mk(5, "A", 0, "t4")} {
		n.AddPool(o)
	}
	var ids []string
	for _, o := range n.PendingCopy() {
		ids = append(ids, o.TrfrID)
	}
	if strings.Join(ids, ",") != "t3,t4,t2,t1" {
		t.Fatalf("order %v", ids)
	}
}

func TestMNReportRoundTrip(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	sign := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	fund := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	n.UpdateOptions(func(o *storageOptions) { o.MNIP = "8.8.8.8"; o.MNPort = "8080"; o.MNSign = sign; o.MNFunds = fund })
	rep := n.MNReportString(10)
	m, ok := ParseMNode("$MNREPO " + rep)
	if !ok || m.IP != "8.8.8.8" || m.Fund != fund {
		t.Fatalf("%v %+v", ok, m)
	}
	if StringFromMN(m) != rep {
		t.Fatalf("\n%s\n%s", StringFromMN(m), rep)
	}
	// Empty list accepts without funds check (COMPAT nosomasternodes.pas:379).
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10) == "" || n.MNsListLen() != 1 {
		t.Fatal("report not accepted")
	}
	// Second report from the same IP is refused.
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10) != "" {
		t.Fatal("duplicate accepted")
	}
	// Zero checks => MinValidations = -1 => everyone listed, age ":1".
	if got := n.MNsAddresses(10); got != "10 8.8.8.8;8080:"+fund+":1" {
		t.Fatal(got)
	}
	n.ClearMNsList()
	if n.MNsAddresses(10) != "10" {
		t.Fatal("empty list gives only the block number")
	}
}
