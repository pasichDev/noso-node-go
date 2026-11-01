package node

import (
	"archive/zip"
	"bytes"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// fundedNode returns a node whose wallet address 0 has mined block 1.
func fundedNode(t *testing.T) (*Node, *int64, types.Wallet) {
	now := int64(consensus.GenesysTimeStamp) + 600
	n := newTestNode(t, &now)
	w := n.Wallet.At(0)
	now += 600
	if _, err := n.BuildNewBlock(1, now, n.MyLastBlockHash(), w.Hash, "x"); err != nil {
		t.Fatal(err)
	}
	now += 90 // inside the block period, order times will be after TimeStart
	return n, &now, w
}

func destAddr() string { return crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0) }

func orderLine(o types.Order, n int) string {
	return "PSK 2 v 1 ORDER 1 $" + types.StringFromOrder(o)
}

// C-04: the TrfrID is derived from the signed fields, so a changed field or
// a re-labelled id is rejected, and a transfer already mined is refused.
func TestC04_TrfrIDBoundAndReplay(t *testing.T) {
	n, now, w := fundedNode(t)
	ts := *now - 30
	o, _ := n.SendFundsFromAddress(w.Hash, destAddr(), 1000000000, 1000000, "ref", itoa(ts), 1)
	if c := n.ValidateTrfr(o, o.Address); c != 0 {
		t.Fatalf("honest order refused: %d", c)
	}
	forged := o
	forged.TrfrID = crypto.GetTransferHash("another id") // same signature, new id (the replay trick)
	if c := n.ValidateTrfr(forged, forged.Address); c != 13 {
		t.Fatalf("C-04: re-labelled TrfrID accepted (code %d)", c)
	}
	forged = o
	forged.Reference = "other" // reference was outside the original signature
	if c := n.ValidateTrfr(forged, forged.Address); c == 0 {
		t.Fatal("C-04/H-07: changed reference accepted")
	}
	forged = o
	forged.OrderType = "CUSTOM"
	if c := n.ValidateTrfr(forged, forged.Address); c == 0 {
		t.Fatal("H-07: changed type accepted")
	}
	// Mine it, then replay the identical signed order in the next period.
	o.OrderID = SingleOrderID(o.TrfrID)
	n.AddPool(o)
	*now += 600 - 90 + 90
	if _, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x"); err != nil {
		t.Fatal(err)
	}
	if !n.TrxSeenRecently(o.TrfrID) {
		t.Fatal("mined order not found in the recent window")
	}
	if c := n.ValidateTrfr(o, o.Address); c == 0 {
		t.Fatal("C-04: replay of a mined transfer accepted")
	}
}

// C-05: amount + fee overflow and negative amounts.
func TestC05_Overflow(t *testing.T) {
	n, now, w := fundedNode(t)
	o, _ := n.SendFundsFromAddress(w.Hash, destAddr(), 1000000000, 1000000, "r", itoa(*now-30), 1)
	o.AmmountTrf = math.MaxInt64 - 5
	o.AmmountFee = 100 // sum wraps negative
	SignOrder(&o, w.PrivateKey)
	if c := n.ValidateTrfr(o, o.Address); c != 15 {
		t.Fatalf("C-05: wrapping sum accepted (code %d)", c)
	}
	o.AmmountTrf, o.AmmountFee = -5, 1000000
	SignOrder(&o, w.PrivateKey)
	if c := n.ValidateTrfr(o, o.Address); c != 7 {
		t.Fatalf("negative amount: %d", c)
	}
	// the summary itself refuses negative and wrapping operations
	n.Summary.ResetBlockRecords()
	before := n.Summary.BalanceIndexed(w.Hash)
	if n.Summary.ValidPay(w.Hash, -1000, 9) || n.Summary.CreditTo(w.Hash, -1, 9) {
		t.Fatal("C-05: negative amounts accepted by the summary")
	}
	if n.Summary.CreditTo(w.Hash, math.MaxInt64, 9) {
		t.Fatal("C-05: credit beyond the supply accepted")
	}
	if n.Summary.BalanceIndexed(w.Hash) != before {
		t.Fatal("balance changed")
	}
	// A pool order that slipped in with wrapping amounts must not be built.
	n.SetPending([]types.Order{o})
	*now += 600
	res, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x")
	if err != nil || len(res.Block.Orders) != 0 {
		t.Fatalf("C-05: overflowing order built into a block: %v", err)
	}
}

// C-06: the CUSTOM fee is exact; a huge declared fee cannot mint coins.
func TestC06_CustomFee(t *testing.T) {
	n, now, w := fundedNode(t)
	mk := func(fee int64, alias string) types.Order {
		o := types.Order{OrderLines: 1, OrderType: "CUSTOM", TimeStamp: *now - 30, Reference: "null", TrxLine: 1,
			Sender: w.PublicKey, Address: w.Hash, Receiver: alias, AmmountFee: fee}
		SignOrder(&o, w.PrivateKey)
		o.OrderID = SingleOrderID(o.TrfrID)
		return o
	}
	greedy := mk(5000000000000, "otheralias") // fee far above the debit
	if c := n.PTCCustom(codecOpData(greedy)); c == 0 {
		t.Fatal("C-06: wrong fee accepted")
	}
	low := mk(1, "thirdalias")
	if c := n.PTCCustom(codecOpData(low)); c == 0 {
		t.Fatal("C-06: fee below the exact fee accepted")
	}
	good := mk(consensus.GetCustFee(1), "validalias")
	if c := n.PTCCustom(codecOpData(good)); c != 0 {
		t.Fatalf("exact fee refused: %d", c)
	}
	n.ClearPending()
	// even if such an order is injected into the pool, the build refuses it
	n.SetPending([]types.Order{greedy})
	*now += 600
	res, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x")
	if err != nil || len(res.Block.Orders) != 0 || res.Block.Header.MinerFee != 0 {
		t.Fatal("C-06: custom order with a forged fee built")
	}
	// M-01: alias rules on the receiving side
	for _, a := range []string{"ab", "has space", "bad!char", destAddr()} {
		o := mk(consensus.GetCustFee(1), a)
		if a == "has space" {
			continue // cannot be expressed on the wire
		}
		if n.PTCCustom(codecOpData(o)) == 0 {
			t.Fatalf("M-01: alias %q accepted", a)
		}
	}
}

func codecOpData(o types.Order) string { return "$" + types.StringFromOrder(o) }

// M-01: only TRFR orders pass PTC_Order.
func TestM01_OrderType(t *testing.T) {
	n, now, w := fundedNode(t)
	o, _ := n.SendFundsFromAddress(w.Hash, destAddr(), 1000000000, 1000000, "r", itoa(*now-30), 1)
	o.OrderType = "PROJCT"
	if c := n.ValidateTrfr(o, o.Address); c != 16 {
		t.Fatalf("type PROJCT accepted: %d", c)
	}
}

// M-14: the owner of a GVT authorises its transfer.
func TestM14_GVTOwner(t *testing.T) {
	n, now, w := fundedNode(t)
	n.GVTs.Replace(append([]byte(nil), mustRead(t, "../../testdata/gvts.psk")...))
	n.GVTs.Reload()
	// give GVT 5 to the wallet address
	n.GVTs.ChangeOwner(5, n.GVTs.Index(5).Owner, w.Hash)
	n.GVTs.Save()
	o := types.Order{OrderLines: 1, OrderType: "SNDGVT", TimeStamp: *now - 30, Reference: "5", TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: destAddr(), AmmountFee: consensus.GetCustFee(1)}
	SignOrder(&o, w.PrivateKey)
	o.OrderID = SingleOrderID(o.TrfrID)
	if c := n.PTCSendGVT(codecOpData(o)); c != 0 {
		t.Fatalf("M-14: owner transfer refused (%d)", c)
	}
	stranger := newWalletAddr(n)
	o2 := o
	o2.Reference, o2.Sender, o2.Address = "6", stranger.PublicKey, stranger.Hash
	SignOrder(&o2, stranger.PrivateKey)
	o2.OrderID = SingleOrderID(o2.TrfrID)
	if c := n.PTCSendGVT(codecOpData(o2)); c == 0 {
		t.Fatal("M-14: transfer of a GVT the sender does not own accepted")
	}
	// Build: the fee is only counted after the debit, the owner changes.
	n.SetPending([]types.Order{o})
	*now += 600
	res, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x")
	if err != nil || len(res.Block.Orders) != 1 || n.GVTs.Index(5).Owner != o.Receiver {
		t.Fatalf("GVT transfer not built: %v", err)
	}
}

// C-01 / H-03: NOSOPAY in the configuration never moves funds, and without a
// configured key no configuration is accepted.
func TestC01_NoSoPayAndSignedConfig(t *testing.T) {
	n, now, w := fundedNode(t)
	dst := destAddr()
	n.CFG.Save(n.CFG.DataStr() + " " + "2," + w.Hash + "," + dst + ",100000:")
	cfgBefore := n.CFG.DataStr()
	_ = cfgBefore
	n.CFG.SetDataStr("NORMAL 204.10.194.22;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE: 2," + w.Hash + "," + dst + ",100000:")
	*now += 600
	if _, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x"); err != nil {
		t.Fatal(err)
	}
	if n.Summary.BalanceIndexed(dst) != 0 {
		t.Fatal("C-01: NOSOPAY transfer executed")
	}
	// signed configuration
	kp := crypto.GenerateKeyPair()
	content := "NORMAL 1.2.3.4;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE:"
	sig := crypto.SignCanonical(kp.PrivateKey, "CFG1", CFGFields(5, content)...)
	if err := n.AcceptConfig(SignedConfig{5, content, sig}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("H-03: accepted without a configured key: %v", err)
	}
	n.UpdateOptions(func(o *storageOptions) { o.ConfigKey = kp.PublicKey })
	if err := n.AcceptConfig(SignedConfig{5, content + "x", sig}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("C-01: modified content accepted: %v", err)
	}
	forgery := crypto.SignCanonical(crypto.GenerateKeyPair().PrivateKey, "CFG1", CFGFields(6, content)...)
	if err := n.AcceptConfig(SignedConfig{6, content, forgery}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("C-01: wrong key accepted: %v", err)
	}
	if err := n.AcceptConfig(SignedConfig{5, content, sig}); err != nil || n.CFG.DataStr() != content {
		t.Fatalf("valid signed config refused: %v", err)
	}
	if err := n.AcceptConfig(SignedConfig{5, content, sig}); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay accepted: %v", err)
	}
	if sc, ok := n.StoredConfig(); !ok || sc.Seq != 5 {
		t.Fatal("stored config not served")
	}
}

// H-02: directives carry a sequence number and expiry.
func TestH02_DirectiveReplay(t *testing.T) {
	n, _, _ := fundedNode(t)
	kp := crypto.GenerateKeyPair()
	n.UpdateOptions(func(o *storageOptions) { o.AdminKey = kp.PublicKey })
	sign := func(seq, exp int64, text string) string {
		return crypto.SignCanonical(kp.PrivateKey, "DIRECTIVE1", DirectiveFields(seq, exp, text)...)
	}
	last := n.MyLastBlock()
	if _, err := n.AcceptDirective(1, last+10, "SETMODE STOP", sign(1, last+10, "SETMODE STOP")); err != nil || n.CFG.Param(0) != "STOP" {
		t.Fatalf("valid directive: %v", err)
	}
	if _, err := n.AcceptDirective(1, last+10, "SETMODE NORMAL", sign(1, last+10, "SETMODE NORMAL")); !errors.Is(err, ErrReplay) {
		t.Fatalf("H-02: replayed sequence accepted: %v", err)
	}
	if _, err := n.AcceptDirective(2, last-1, "SETMODE NORMAL", sign(2, last-1, "SETMODE NORMAL")); !errors.Is(err, ErrExpired) {
		t.Fatalf("H-02: expired directive accepted: %v", err)
	}
	if _, err := n.AcceptDirective(3, last+10, "UPDATE 9.9.9", sign(3, last+10, "SETMODE NORMAL")); !errors.Is(err, ErrBadSig) {
		t.Fatal("text not covered by the signature")
	}
	// no update/restart/fund directive has any effect (C-08, H-03)
	cfg := n.CFG.DataStr()
	_, _ = n.AcceptDirective(4, last+10, "ADDNOSOPAY x", sign(4, last+10, "ADDNOSOPAY x"))
	if n.CFG.DataStr() != cfg {
		t.Fatal("ADDNOSOPAY directive changed the configuration")
	}
	n.UpdateOptions(func(o *storageOptions) { o.AdminKey = "" })
	if _, err := n.AcceptDirective(9, last+10, "SETMODE X", sign(9, last+10, "SETMODE X")); !errors.Is(err, ErrNoKey) {
		t.Fatal("H-03: directive accepted without a configured key")
	}
}

func zipOf(t *testing.T, files map[string][]byte) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range files {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	return b.Bytes()
}

// C-02: archive hygiene. C-03: blocks must validate.
func TestC02_C03_StageBlocks(t *testing.T) {
	bd := newBed(t, 2)
	a, b := bd.nodes[0], bd.nodes[1]
	bd.build(a)
	blk1 := mustRead(t, a.Lay.BlockFile(1))

	for _, name := range []string{"../evil.blk", "NOSODATA/BLOCKS/1.blk", "/etc/passwd", "1.txt", "sub/1.blk"} {
		if _, err := b.StageBlocks(zipOf(t, map[string][]byte{name: blk1})); err == nil {
			t.Fatalf("C-02: entry name %q accepted", name)
		}
	}
	if _, err := os.Stat(b.Lay.Root + "/../evil.blk"); err == nil {
		t.Fatal("file written outside the block directory")
	}
	// parent hash mismatch
	hdr := types.DecodeHeader(blk1)
	hdr.LastBlockHash = "DEADBEEF"
	forged := append(hdr.Encode(), blk1[types.HeaderSize:]...)
	if _, err := b.StageBlocks(zipOf(t, map[string][]byte{"1.blk": forged})); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("C-03: block with a wrong parent accepted: %v", err)
	}
	// wrong reward
	hdr = types.DecodeHeader(blk1)
	hdr.Reward *= 2
	forged = append(hdr.Encode(), blk1[types.HeaderSize:]...)
	if _, err := b.StageBlocks(zipOf(t, map[string][]byte{"1.blk": forged})); !errors.Is(err, ErrInvalidBlock) {
		t.Fatalf("C-03: inflated reward accepted: %v", err)
	}
	if b.MyLastBlock() != 0 {
		t.Fatal("invalid block stored")
	}
	// a valid block is stored
	if cnt, err := b.StageBlocks(zipOf(t, map[string][]byte{"1.blk": blk1})); err != nil || cnt != 1 || b.MyLastBlock() != 1 {
		t.Fatalf("valid block refused: %d %v", cnt, err)
	}
	sameState(t, a, b)
}

// C-03: replay of an unfunded transfer rolls the block back.
func TestC03_ReplayRollsBack(t *testing.T) {
	n, now, w := fundedNode(t)
	o, _ := n.SendFundsFromAddress(w.Hash, destAddr(), 1000000000, 1000000, "r", itoa(*now-30), 1)
	n.AddPool(o)
	*now += 600
	if _, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), destAddr(), "x"); err != nil {
		t.Fatal(err)
	}
	// break the funding: replay on a summary where the sender is empty
	n.Summary.CreateNew(true)
	n.Summary.SetLastOp(1)
	n.SetMyLastBlock(2)
	err := n.CompleteSummary()
	if err == nil {
		t.Fatal("C-03: unfunded replay not detected")
	}
	if n.MyLastBlock() >= 2 {
		t.Fatalf("bad blocks not removed, last=%d", n.MyLastBlock())
	}
}

// H-04: reorganisation depth is bounded.
func TestH04_ReorgDepth(t *testing.T) {
	n, now, w := fundedNode(t)
	for i := int64(2); i <= 30; i++ {
		*now = consensus.GenesysTimeStamp + 600*(i+1)
		if _, err := n.BuildNewBlock(i, *now, n.MyLastBlockHash(), w.Hash, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if n.RemoveBlocks(1) != -1 || n.MyLastBlock() != 30 {
		t.Fatal("H-04: a 30 block deletion was allowed")
	}
	if n.RemoveBlocks(0) != -1 { // would have looped forever in Pascal
		t.Fatal("RemoveBlocks(0)")
	}
	if got := n.RemoveBlocks(28); got != 3 || n.MyLastBlock() != 27 {
		t.Fatalf("bounded removal: %d last=%d", got, n.MyLastBlock())
	}
}

// M-12: a failed write stops the node instead of advancing.
func TestM12_WriteFailureStopsBuild(t *testing.T) {
	n, now, w := fundedNode(t)
	_ = os.Chmod(n.Lay.BlockDir, 0o500)
	defer os.Chmod(n.Lay.BlockDir, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	*now += 600
	if _, err := n.BuildNewBlock(2, (*now/600)*600, n.MyLastBlockHash(), w.Hash, "x"); err == nil {
		t.Fatal("M-12: build succeeded although the block could not be written")
	}
	if n.MyLastBlock() != 1 {
		t.Fatal("chain advanced after a failed write")
	}
}

// L-01 / L-08: receivers.
func TestL01_L08_Receivers(t *testing.T) {
	good := destAddr()
	if !ValidReceiver(good) || ValidReceiver("M"+good[1:]) || ValidReceiver(good+strings.Repeat("1", 20)) || ValidReceiver("") {
		t.Fatal("receiver rules")
	}
	n, _, _ := fundedNode(t)
	long := "N" + strings.Repeat("a", 60)
	n.Summary.ResetBlockRecords()
	if n.Summary.CreditTo(long, 5, 3) {
		t.Fatal("L-08: over-long name stored (truncated) in the summary")
	}
}

// L-03: unparsable orders are errors, and the first error code of a line is
// kept.
func TestL03_ResultsAtEntry(t *testing.T) {
	n, _, _ := fundedNode(t)
	if n.PTCCustom("garbage") == 0 || n.PTCSendGVT("garbage") == 0 {
		t.Fatal("L-03: unparsable order answered with success")
	}
	if got := n.PTCOrder("PSK 2 v 1 ORDER 31 $x"); got != "ERROR 89" {
		t.Fatalf("too many transfers: %q", got)
	}
	if got := n.PTCOrder("PSK 2 v 1 ORDER x"); got != "" {
		t.Fatalf("non numeric count: %q", got)
	}
	// a transfer whose id is wrong: the line is refused with a code, not ""
	n2, now, w := fundedNode(t)
	o, _ := n2.SendFundsFromAddress(w.Hash, destAddr(), 1000000000, 1000000, "r", itoa(*now-30), 1)
	o.TrfrID = "tRbogus"
	o.OrderLines = 1
	genID := crypto.GetOrderHash("1" + itoa(o.TimeStamp) + o.TrfrID)
	o.OrderID = genID
	line := "PSK 2 v 1 ORDER 1 $" + types.StringFromOrder(o)
	if got := n2.PTCOrder(line); !strings.HasPrefix(got, "ERROR") {
		t.Fatalf("L-03: rejected order answered with %q", got)
	}
}
