package types

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

func TestRecordSizes(t *testing.T) {
	if len((&Summary{}).Encode()) != SummarySize || len(Resumen{}.Encode()) != ResumenSize ||
		len(BlockHeader{}.Encode()) != HeaderSize || len(Order{}.Encode()) != OrderSize ||
		len(GVT{}.Encode()) != GVTSize || len(Wallet{}.Encode()) != WalletSize ||
		len(MNLock{}.Encode()) != MNLockSize || len(DBRecord{}.Encode()) != DBRecSize {
		t.Fatal("record size mismatch")
	}
}

// Golden: the real mainnet summary at block 59238 (59238.psk) round-trips
// byte for byte and every account address passes IsValidHashAddress.
func TestGoldenSummary59238(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/59238.psk")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%SummarySize != 0 {
		t.Fatalf("size %d not a multiple of %d", len(raw), SummarySize)
	}
	n := len(raw) / SummarySize
	if n != 4956 {
		t.Fatalf("records %d", n)
	}
	var out bytes.Buffer
	invalid := 0
	for i := 0; i < n; i++ {
		rec := raw[i*SummarySize : (i+1)*SummarySize]
		s := DecodeSummary(rec)
		out.Write(s.Encode())
		if !crypto.IsValidHashAddress(s.Hash) {
			invalid++
			// Real mainnet data: CreditTo never validates the receiver, so a
			// transfer to a garbage string created these accounts, stored
			// truncated to the String[40] capacity.
			if !strings.HasPrefix(s.Hash, "androidx.lifecycle.MutableLiveData@") || len(s.Hash) != 40 {
				t.Errorf("unexpected invalid address %q", s.Hash)
			}
		}
	}
	if !bytes.Equal(out.Bytes(), raw) {
		t.Fatal("summary round trip differs")
	}
	first := DecodeSummary(raw[:SummarySize])
	// Record 0 is the genesis account, whose LastOP holds the last block.
	if first.Hash != "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd" || first.LastOP != 59238 {
		t.Fatalf("%+v", first)
	}
	t.Logf("accounts=%d invalid-address-checksums=%d", n, invalid)
	if invalid != 11 {
		t.Fatalf("expected the 11 garbage accounts of block 59238, got %d", invalid)
	}
}

func TestGoldenGVTs(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/gvts.psk")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 100*GVTSize {
		t.Fatalf("size %d", len(raw))
	}
	var out bytes.Buffer
	for i := 0; i < 100; i++ {
		g := DecodeGVT(raw[i*GVTSize : (i+1)*GVTSize])
		out.Write(g.Encode())
		if len(g.Number) != 2 || !crypto.IsValidHashAddress(g.Owner) || len(g.Hash) != 64 {
			t.Fatalf("gvt %d: %+v", i, g)
		}
	}
	if !bytes.Equal(out.Bytes(), raw) {
		t.Fatal("gvts round trip differs")
	}
	g0 := DecodeGVT(raw)
	if g0.Number != "00" || g0.Owner != "N2vWyg8xm1JK3CDb8VfRxpEAnbmJWEF" {
		t.Fatalf("%+v", g0)
	}
}

func TestOrderStringRoundTrip(t *testing.T) {
	o := Order{OrderID: "ORabc", OrderLines: 1, OrderType: "TRFR", TimeStamp: 1700000000,
		Reference: "null", TrxLine: 1, Sender: "PUB", Address: "NAddr", Receiver: "NRecv",
		AmmountFee: 1000000, AmmountTrf: 123456789, Signature: "SIG", TrfrID: "tRxyz"}
	line := StringFromOrder(o)
	if line != "TRFR ORabc 1 TRFR 1700000000 null 1 PUB NAddr NRecv 1000000 123456789 SIG tRxyz" {
		t.Fatal(line)
	}
	got, ok := ParseOrder(line)
	if !ok || !bytes.Equal(got.Encode(), o.Encode()) || got.OrderID != o.OrderID {
		t.Fatalf("%v %+v", ok, got)
	}
	// FIX(L-08): over-long fields are rejected instead of truncated.
	if _, ok := ParseOrder("X id 1 TRFRXXX 5 null 1 s a r 0 0 sig t"); ok {
		t.Fatal("over-long order type accepted")
	}
	long := "N" + strings.Repeat("a", 45)
	if _, ok := ParseOrder("X id 1 TRFR 5 null 1 s a " + long + " 0 0 sig t"); ok {
		t.Fatal("over-long receiver accepted")
	}
	if _, ok := ParseOrder("X id one TRFR 5 null 1 s a r 0 0 sig t"); ok {
		t.Fatal("bad int must fail")
	}
	if !bytes.Equal(DecodeOrder(o.Encode()).Encode(), o.Encode()) {
		t.Fatal("order bytes")
	}
}

func TestHeaderLayout(t *testing.T) {
	h := BlockHeader{Number: 5, TimeStart: 10, TimeEnd: 20, TimeTotal: 10, TrxTotales: 2,
		TargetHash: "T", Solution: "S", LastBlockHash: "L", NxtBlkDiff: 7, AccountMiner: "M",
		MinerFee: 9, Reward: 11}
	b := h.Encode()
	if !bytes.Equal(DecodeHeader(b).Encode(), b) || DecodeHeader(b).Reward != h.Reward {
		t.Fatal("header round trip")
	}
	if b[40] != 1 || b[41] != 'T' || b[73] != 1 || b[274] != 1 || b[311] != 1 {
		t.Fatal("string offsets")
	}
}

func TestShortStringTailPreserved(t *testing.T) {
	raw := make([]byte, SummarySize)
	copy(raw[41:], "\x05ALIAS")
	s := DecodeSummary(raw)
	s.Custom = "AB" // shorter assignment leaves stale bytes after the new end
	out := s.Encode()
	if string(out[41:48]) != "\x02ABIAS\x00" {
		t.Fatalf("%q", out[41:48])
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(make([]byte, OrderSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		pad := func(n int) []byte {
			x := make([]byte, n)
			copy(x, b)
			return x
		}
		DecodeOrder(pad(OrderSize))
		DecodeHeader(pad(HeaderSize))
		DecodeSummary(pad(SummarySize))
		DecodeGVT(pad(GVTSize))
		DecodeWallet(pad(WalletSize))
		DecodeResumen(pad(ResumenSize))
		ParseOrder(string(b))
	})
}

// Item 5 of the rewrite review: the stale tail of a shortened ShortString
// survives in Order, BlockHeader, Resumen and MNLock like in Summary, and a
// Pascal style assignment of the address over the public key keeps the key
// tail in the Sender bytes (mpblock.pas:199,212,227). Layouts are derived
// from the packed record declarations, not from a Pascal run.
func TestShortStringTailsPreservedEverywhere(t *testing.T) {
	raw := make([]byte, OrderSize)
	copy(raw[157:], "\x0aABCDEFGHIJ") // Sender, length 10
	o := DecodeOrder(raw)
	o.Sender = "XY"
	b := o.Encode()
	if b[157] != 2 || string(b[158:160]) != "XY" || string(b[160:167]) != "CDEFGHI" {
		t.Fatalf("order tail lost: %q", b[157:170])
	}
	n := Order{Sender: "PUBLICKEYPUBLICKEY", Address: "NADDR"}
	n.AssignSender(n.Address)
	nb := n.Encode()
	if nb[157] != 5 || string(nb[158:163]) != "NADDR" || string(nb[163:176]) != "CKEYPUBLICKEY" {
		t.Fatalf("AssignSender: %q", nb[157:180])
	}
	if got := DecodeOrder(nb); got.Sender != "NADDR" || !bytes.Equal(got.Encode(), nb) {
		t.Fatal("round trip of an order with a stale tail")
	}
	hraw := make([]byte, HeaderSize)
	copy(hraw[311:], "\x08ABCDEFGH")
	h := DecodeHeader(hraw)
	h.AccountMiner = "Z"
	if hb := h.Encode(); hb[311] != 1 || string(hb[312:316]) != "ZBCD" {
		t.Fatal("header tail lost")
	}
	rraw := make([]byte, ResumenSize)
	copy(rraw[37:], "\x06ABCDEF")
	r := DecodeResumen(rraw)
	r.SumHash = "Q"
	if rb := r.Encode(); string(rb[38:42]) != "QBCD" {
		t.Fatal("resumen tail lost")
	}
	mraw := make([]byte, MNLockSize)
	copy(mraw[0:], "\x05ABCDE")
	mraw[34] = 0x7f // padding byte
	m := DecodeMNLock(mraw)
	m.Address = "A"
	if mb := m.Encode(); string(mb[2:6]) != "BCDE" || mb[34] != 0x7f {
		t.Fatal("mnlock tail or padding lost")
	}
	if !bytes.Equal(DecodeMNLock(mraw).Encode(), mraw) {
		t.Fatal("mnlock round trip")
	}
}
