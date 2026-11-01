package storage

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/types"
)

// GOLDEN VECTORS, DERIVED. Of the files in testdata/, 59238.psk and gvts.psk
// are real files written by the Pascal node (byte-identical to the originals
// in the NosoNode source tree, used in types_test.go). No block, wallet,
// headers or psos file written by the Pascal node is available, so each
// vector below is assembled by hand, byte offset by byte offset, from
// the packed record declarations in the Pascal source (cited per test). The
// builders use encoding/binary and explicit offsets, not the code under test.
// They prove that the Go codec agrees with the layout as read from the
// declarations; they do not prove the declarations were read correctly.

type lay struct{ b []byte }

func (l *lay) short(off, max int, s string) {
	if len(s) > max {
		panic("string too long for field")
	}
	l.b[off] = byte(len(s))
	copy(l.b[off+1:], s)
}
func (l *lay) i32(off int, v int32) { binary.LittleEndian.PutUint32(l.b[off:], uint32(v)) }
func (l *lay) i64(off int, v int64) { binary.LittleEndian.PutUint64(l.b[off:], uint64(v)) }

// TOrderData, nosogeneral.pas:26-41, packed: 562 bytes.
func goldenOrder() []byte {
	l := &lay{make([]byte, 562)}
	l.i32(0, 48500)                                 // Block
	l.short(4, 64, "ORgolden")                      // OrderID  String[64]
	l.i32(69, 1)                                    // OrderLines
	l.short(73, 6, "TRFR")                          // OrderType String[6]
	l.i64(80, 1700000000)                           // TimeStamp
	l.short(88, 64, "ref")                          // Reference String[64]
	l.i32(153, 1)                                   // TrxLine
	l.short(157, 120, "NSENDER0000")                // Sender String[120]
	copy(l.b[157+1+11:], "PUBKEYTAIL")              // stale tail of a longer public key
	l.short(278, 40, "NADDRESS0000000000000000000") // Address String[40]
	l.short(319, 40, "NRECEIVER")                   // Receiver String[40]
	l.i64(360, 1000000)                             // AmmountFee
	l.i64(368, 123456789)                           // AmmountTrf
	l.short(376, 120, "SIGNATURE")                  // Signature String[120]
	l.short(497, 64, "tRtransfer")                  // TrfrID String[64]
	return l.b
}

// BlockHeaderData, nosoblock.pas:25-40, packed: 368 bytes.
func goldenHeader() []byte {
	l := &lay{make([]byte, 368)}
	l.i64(0, 48500)
	l.i64(8, 1700000000)
	l.i64(16, 1700000600)
	l.i32(24, 600)
	l.i32(28, 598)
	l.i32(32, 1) // TrxTotales
	l.i32(36, 91)
	l.short(40, 32, "TARGETHASH")
	l.short(73, 200, "SOLUTION")
	l.short(274, 32, "LASTBLOCKHASH")
	l.i32(307, 90)
	l.short(311, 40, "NMINER")
	l.i64(352, 1000000)
	l.i64(360, 5000000)
	return l.b
}

func TestGoldenBlockFile(t *testing.T) {
	// N.blk for a block >= MNBlockStart (mpblock.pas:503-545 GuardarBloque):
	// header, orders, PosPay int64 + PoSnumber int32 + addresses (String[32],
	// 33 bytes each), MNsPay int64 + MNsNumber int32 + addresses.
	var raw []byte
	raw = append(raw, goldenHeader()...)
	raw = append(raw, goldenOrder()...)
	pos := make([]byte, 12+33)
	binary.LittleEndian.PutUint64(pos, 2500000)
	binary.LittleEndian.PutUint32(pos[8:], 1)
	pos[12] = 8
	copy(pos[13:], "NPOSADDR")
	mn := make([]byte, 12+33*2)
	binary.LittleEndian.PutUint64(mn, 4700000)
	binary.LittleEndian.PutUint32(mn[8:], 2)
	mn[12] = 4
	copy(mn[13:], "NMN1")
	mn[12+33] = 4
	copy(mn[13+33:], "NMN2")
	raw = append(raw, pos...)
	raw = append(raw, mn...)

	b, err := DecodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := b.Header
	if h.Number != 48500 || h.TimeTotal != 600 || h.TargetHash != "TARGETHASH" || h.Solution != "SOLUTION" ||
		h.LastBlockHash != "LASTBLOCKHASH" || h.NxtBlkDiff != 90 || h.AccountMiner != "NMINER" || h.Reward != 5000000 {
		t.Fatalf("header %+v", h)
	}
	if len(b.Orders) != 1 {
		t.Fatal("orders")
	}
	o := b.Orders[0]
	if o.OrderID != "ORgolden" || o.OrderType != "TRFR" || o.Sender != "NSENDER0000" || o.Receiver != "NRECEIVER" ||
		o.AmmountTrf != 123456789 || o.Signature != "SIGNATURE" || o.TrfrID != "tRtransfer" {
		t.Fatalf("order %+v", o)
	}
	if b.PosPay != 2500000 || len(b.PosAddrs) != 1 || b.PosAddrs[0] != "NPOSADDR" ||
		b.MNsPay != 4700000 || len(b.MNsAddrs) != 2 || b.MNsAddrs[1] != "NMN2" {
		t.Fatalf("tails %+v", b)
	}
	// re-encoding reproduces every byte, including the stale public key tail
	if !bytes.Equal(b.Encode(), raw) {
		t.Fatal("block does not re-encode byte for byte")
	}
	if !bytes.Contains(b.Encode(), []byte("PUBKEYTAIL")) {
		t.Fatal("stale tail dropped")
	}
}

// psos.dat, nosopsos.pas:23-37, 138-240: TPSOHeader (3 x Int32), TMNsLock
// (String[32] + 3 padding + Int32 = 40, unpacked), then per PSO a Word mode,
// Word-prefixed Hash and Owner, DWord Expire, Word-prefixed Members, Params.
func goldenPSOs() []byte {
	var b bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&b, binary.LittleEndian, v) }
	w32 := func(v int32) { _ = binary.Write(&b, binary.LittleEndian, v) }
	str := func(s string) { w16(uint16(len(s))); b.WriteString(s) }
	w32(48500) // Block
	w32(1)     // MNsLock
	w32(1)     // Count
	lock := make([]byte, 40)
	lock[0] = 6
	copy(lock[1:], "NLOCKD")
	copy(lock[33:], []byte{0xAA, 0xBB, 0xCC}) // padding bytes
	binary.LittleEndian.PutUint32(lock[36:], 50516)
	b.Write(lock)
	w16(3)
	str("HASH")
	str("NOWNER")
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xFFFFFFFF))
	str("M1,M2")
	str("param")
	return b.Bytes()
}

func TestGoldenPSOs(t *testing.T) {
	raw := goldenPSOs()
	if !ValidPSOFile(raw) {
		t.Fatal("golden psos.dat refused")
	}
	l := tmp(t)
	if err := os.WriteFile(l.PSOs, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	p := OpenPSOs(l.PSOs)
	if p.Header().Block != 48500 || p.LockedCount() != 1 {
		t.Fatalf("%+v", p.Header())
	}
	if m := p.LockedAt(0); m.Address != "NLOCKD" || m.Expire != 50516 {
		t.Fatalf("%+v", m)
	}
	if len(p.psos) != 1 || p.psos[0].Mode != 3 || p.psos[0].Owner != "NOWNER" || p.psos[0].Params != "param" {
		t.Fatalf("%+v", p.psos)
	}
	if p.psos[0].Expire != -1 { // DWord FFFFFFFF is read into an Integer
		t.Fatalf("expire %d", p.psos[0].Expire)
	}
	// saving reproduces the file, padding bytes included
	if err := p.Save(48500); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(l.PSOs)
	if !bytes.Equal(got, raw) {
		t.Fatalf("psos.dat changed on save\n% x\n% x", got, raw)
	}
}

// Truncated string at the end: ReadBuffer raises in Pascal, the file counts as
// errored (nosopsos.pas:192-195).
func TestPSOTruncatedStringRefused(t *testing.T) {
	raw := goldenPSOs()
	bad := raw[:len(raw)-2] // "param" loses two bytes, its Word length stays 5
	l := tmp(t)
	if err := os.WriteFile(l.PSOs, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	p := &PSOs{path: l.PSOs}
	if p.parse(bad) {
		t.Fatal("truncated psos.dat parsed")
	}
	lockCut := raw[:PSOHdrBytes+20] // lock record cut in half
	if (&PSOs{}).parse(lockCut) {
		t.Fatal("truncated lock accepted")
	}
}

// wallet.pkw, nosowallcon.pas:18-27: Hash/Custom String[40], PublicKey and
// PrivateKey String[255], Balance, Pending, Score, LastOP Int64: 626 bytes.
func TestGoldenWalletPKW(t *testing.T) {
	l := &lay{make([]byte, 626)}
	l.short(0, 40, "NHASHADDRESS")
	l.short(41, 40, "alias")
	l.short(82, 255, "PUBLICKEYBASE64")
	l.short(338, 255, "PRIVATEKEYBASE64")
	l.i64(594, 111)
	l.i64(602, 222)
	l.i64(610, 333)
	l.i64(618, 444)
	d := types.DecodeWallet(l.b)
	if d.Hash != "NHASHADDRESS" || d.Custom != "alias" || d.PublicKey != "PUBLICKEYBASE64" ||
		d.PrivateKey != "PRIVATEKEYBASE64" || d.Balance != 111 || d.Pending != 222 || d.Score != 333 || d.LastOP != 444 {
		t.Fatalf("%+v", d)
	}
	if !bytes.Equal(d.Encode(), l.b) {
		t.Fatal("wallet record does not re-encode")
	}
	// as a file: a plain wallet opens, VerifyOnDisk finds the address, and the
	// bytes survive a Save
	lay := tmp(t)
	if err := os.WriteFile(lay.Wallet, l.b, 0o600); err != nil {
		t.Fatal(err)
	}
	w, existed := OpenWallet(lay.Wallet)
	if !existed || w.Len() != 1 || !w.VerifyOnDisk("NHASHADDRESS") {
		t.Fatal("open")
	}
	w.Save()
	if got, _ := os.ReadFile(lay.Wallet); !bytes.Equal(got, l.b) {
		t.Fatal("wallet.pkw changed on save")
	}
}

// advopt.txt as CreateADV writes it (mpdisk.pas:232-308), typed by hand. The
// port appends its own "Security" section before "Deprecated", so only the
// Pascal part is compared line by line.
const goldenAdvopt = `---NosoNode config file.---

---Wallet related.---
//Hide empty addresses
HideEmpty True
//Use all addresses to send funds
MultiSend False
//Po files language code
Language en
//No GUI refresh
NoGUI False
//Po files last update
PoUpdate 0.0.0
//Close the launch form automatically
Closestart True
//Send anonymous report to developers
SendReport False
//Keep a blocks database
BlocksDB True
//Restart periodically the node
PRestart 12
//Skip new blocks creation
SkipBlocks False
//Mainform coordinates. Do not manually change this values
FormState 10 20 800 600 2

---Masternode---
//Enable node server at start
Autoserver True
//Run autoupdate directives
Autoupdate False
//Download the complete blockchain
WO_FullNode True
//Masternode static IP
MNIP 1.2.3.4
//Masternode port
MNPort 8080
//Masternode funds address
MNFunds NFUNDS
//Masternode sign address
MNSign NSIGN
//Use automatic IP detection for masternode
MNAutoIp False

---RPC server---
//RPC server port
RPCPort 8078
//RPC server password
RPCPass secret
//RPC IP filter active/inactive
RPCFilter True
//RPC whitelisted IPs
RPCWhiteList 127.0.0.1,localhost
//Enable RPC server at start
RPCAuto False
//Save addresses keys created on a BAK folder
RPCSaveNew False
//Banned methods for RPC requests
RPCBanned getmainnetinfo
`

func TestGoldenAdvopt(t *testing.T) {
	l := tmp(t)
	if err := os.WriteFile(l.AdvOpt, []byte(goldenAdvopt+"\n---Deprecated. To be removed.---\nMaxPeers 40\nPosWarning 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions("x")
	if err := o.Load(l.AdvOpt); err != nil {
		t.Fatal(err)
	}
	if !o.HideEmpty || o.MultiSend || o.Language != "en" || o.PRestart != 12 || o.FormState != [5]int64{10, 20, 800, 600, 2} ||
		o.MNIP != "1.2.3.4" || o.MNSign != "NSIGN" || o.RPCPass != "secret" || o.RPCBanned != "getmainnetinfo" ||
		o.MaxPeers != 40 || o.PosWarning != 5 || o.AutoUpdate {
		t.Fatalf("%+v", o)
	}
	out := tmp(t)
	if err := o.Save(out.AdvOpt); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out.AdvOpt)
	i := strings.Index(string(got), "---Security (added by this port)---")
	j := strings.Index(string(got), "---Deprecated.")
	if i < 0 || j < i {
		t.Fatal("sections")
	}
	pascalPart := string(got[:i])
	if pascalPart != goldenAdvopt+"\n" {
		t.Fatalf("Pascal part differs:\n%s\n----\n%s", pascalPart, goldenAdvopt)
	}
	if !strings.HasSuffix(string(got), "---Deprecated. To be removed.---\nMaxPeers 40\nPosWarning 5\n") {
		t.Fatal("deprecated section")
	}
}
