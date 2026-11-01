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
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
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
	if err := b.RebuildSummary(); err != nil {
		t.Fatal(err)
	}
	if b.Summary.BalanceIndexed(miner) != a.Summary.BalanceIndexed(miner) ||
		b.Summary.BalanceIndexed(dest) != a.Summary.BalanceIndexed(dest) {
		t.Fatal("replayed balances differ")
	}
	// FIX(M-11): the replay touches the same account as the build path.
	if b.Summary.AddressLastOP(storageGenesis) != 2 || b.Summary.Len() != a.Summary.Len() {
		t.Fatalf("replay genesis LastOP=%d len b=%d a=%d", b.Summary.AddressLastOP(storageGenesis), b.Summary.Len(), a.Summary.Len())
	}
	if a.Summary.AddressLastOP(storageGenesis) != 2 {
		t.Fatal("genesis account LastOP after build")
	}
}

const storageGenesis = "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"

// FIX(8425): the original divided by zero at block 8425 and stopped. The
// chain has an explicit rule now: nobody is paid as a staker and the share
// stays with the miner.
func TestPoSRangeNoLongerStops(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	n.SetMyLastBlock(8424)
	now += 600
	r, err := n.BuildNewBlock(8425, now, "", "N1", "x")
	if err != nil || r == nil || r.Block.PosPay != 0 || len(r.Block.PosAddrs) != 0 {
		t.Fatalf("block 8425: %v %v", r, err)
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

func TestMNReportSecurity(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	fund := n.Wallet.At(0).Hash
	signW := newWalletAddr(n)
	setOpts := func() {
		n.UpdateOptions(func(o *storageOptions) {
			o.MNIP = "8.8.8.8"
			o.MNPort = "8080"
			o.MNSign = signW.Hash
			o.MNFunds = fund
		})
	}
	setOpts()
	// H-01: a report from an address without the funds is refused even when
	// the list is empty (the original skipped the check for the first report).
	rep := n.MNReportString(10)
	if rep == "" {
		t.Fatal("no report produced")
	}
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10) != "" {
		t.Fatal("H-01: first report accepted without funds")
	}
	n.Summary.ResetBlockRecords()
	n.Summary.CreditTo(fund, consensus.GetStackRequired(11), 1)
	_ = n.Summary.UpdateChanges()
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10) == "" || n.MNsListLen() != 1 {
		t.Fatal("funded, signed report refused")
	}
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10) != "" {
		t.Fatal("duplicate accepted")
	}
	n.ClearMNsList()
	// Forged: the same data signed by another key.
	m, _ := ParseMNode("$MNREPO " + rep)
	forged := m
	other := newWalletAddr(n)
	forged.Pub = other.PublicKey
	forged.Sig = crypto.SignCanonical(other.PrivateKey, "MNREPORT1", mnReportFields(forged)...)
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+StringFromMN(forged), 10) != "" {
		t.Fatal("H-01: report signed by a key that is not the fund owner accepted")
	}
	// Validations must start at zero.
	pre := m
	pre.Validations = 50
	pre.Sig = crypto.SignCanonical(n.Wallet.At(0).PrivateKey, "MNREPORT1", mnReportFields(pre)...)
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+StringFromMN(pre), 10) != "" {
		t.Fatal("H-01: pre-loaded validations accepted")
	}
	// A stale report (other block) is refused.
	if n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 11) != "" {
		t.Fatal("H-01: report not bound to the block")
	}
	// Zero checks => every node is listed.
	n.CheckMNReport("PSK 2 v 1 $MNREPO "+rep, 10)
	if got := n.MNsAddresses(10); got != "10 8.8.8.8;8080:"+fund+":1" {
		t.Fatal(got)
	}
}

func newWalletAddr(n *Node) types.Wallet {
	kp := crypto.GenerateKeyPair()
	w := types.Wallet{Hash: crypto.GetAddressFromPublicKey(kp.PublicKey, 0), PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}
	n.Wallet.Insert(w)
	return w
}

// C-07: only registered validators with the registered key can add checks,
// and duplicated IPs inside one check count once.
func TestMNChecksSecurity(t *testing.T) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	v := newWalletAddr(n)
	evil := newWalletAddr(n)
	n.UpdateOptions(func(o *storageOptions) { o.ValidatorKeys = "9.9.9.9=" + v.Hash })
	mk := func(w types.Wallet, ip, nodes string) string {
		c := MNCheck{ValidatorIP: ip, Block: int32(n.MyLastBlock()), SignAddress: w.Hash, PubKey: w.PublicKey, ValidNodes: nodes}
		c.Signature = crypto.SignCanonical(w.PrivateKey, "MNCHECK1", MNCheckFields(c)...)
		return "PSK 2 v 1 $MNCHECK " + StringFromMNCheck(c)
	}
	if n.ValidateMNCheck(mk(evil, "9.9.9.9", "8.8.8.8;8080:")) != "" {
		t.Fatal("C-07: check signed by an unregistered key accepted")
	}
	if n.ValidateMNCheck(mk(evil, "7.7.7.7", "8.8.8.8;8080:")) != "" {
		t.Fatal("C-07: unregistered validator IP accepted")
	}
	if n.ValidateMNCheck(mk(v, "9.9.9.9", "8.8.8.8;8080:8.8.8.8;8080:8.8.8.8;8080:")) == "" {
		t.Fatal("registered validator refused")
	}
	n.mn.list = []MNode{{IP: "8.8.8.8", Port: 8080}}
	n.CreditMNVerifications()
	if n.mn.list[0].Validations != 1 {
		t.Fatalf("C-07: repeated IP counted %d times", n.mn.list[0].Validations)
	}
}
