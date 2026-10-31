package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func tmp(t *testing.T) Layout {
	l := NewLayout(filepath.Join(t.TempDir(), "NOSODATA"))
	if l.EnsureDirs() != 0 {
		t.Fatal("dirs")
	}
	return l
}

func TestSummaryGolden59238(t *testing.T) {
	l := tmp(t)
	raw, _ := os.ReadFile("../../testdata/59238.psk")
	if err := os.WriteFile(l.Summary, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	s := OpenSummary(l.Summary)
	if s.Len() != 4956 || s.LastOp() != 59238 {
		t.Fatalf("len=%d lastop=%d", s.Len(), s.LastOp())
	}
	if s.BalanceIndexed(GenesisAddress) != 1042008032156 {
		t.Fatalf("genesis balance %d", s.BalanceIndexed(GenesisAddress))
	}
	if slot, r := s.GetIndexPosition("AllForOne", true); slot != 12 || r.Hash != "N7kKEo1LLdmd6QwEff1hC7bdMUeCCc" {
		t.Fatalf("alias lookup %d %+v", slot, r)
	}
	if s.Hash() != crypto.IDHashBytes(raw) {
		t.Fatal("hash")
	}

	// A block: pay, credit, customise, then flush and compare to the file.
	s.ResetBlockRecords()
	a := "N24oBNscYwaVc6yKRzyUcTznUGcbcGW" // Aelis, 643228805230
	if !s.ValidPay(a, 1000, 59239) {
		t.Fatal("valid pay")
	}
	if s.ValidPay(a, 1<<60, 59239) {
		t.Fatal("overdraft accepted")
	}
	s.CreditTo("NbrandNewAddress1234567890abcdefg", 77, 59239)
	s.CreditTo(GenesisAddress, 0, 59239)
	s.UpdateChanges()
	if s.Len() != 4957 || s.LastOp() != 59239 {
		t.Fatalf("after: %d %d", s.Len(), s.LastOp())
	}
	after, _ := os.ReadFile(l.Summary)
	if len(after) != len(raw)+types.SummarySize {
		t.Fatal("file not extended by exactly one record")
	}
	// Only the touched records differ.
	diff := 0
	for i := 0; i < len(raw)/types.SummarySize; i++ {
		if !bytes.Equal(raw[i*106:(i+1)*106], after[i*106:(i+1)*106]) {
			diff++
		}
	}
	if diff != 2 {
		t.Fatalf("%d records changed, want 2", diff)
	}
	if s.BalanceIndexed(a) != 643228805230-1000 {
		t.Fatal("balance")
	}
	// Reopening yields the same state.
	s2 := OpenSummary(l.Summary)
	if s2.Hash() != s.Hash() || s2.Len() != s.Len() {
		t.Fatal("reopen")
	}
}

// FIX(L-08, C-05): a long "address" is refused instead of being truncated
// into a second account, and negative credits are refused.
func TestSummaryRefusesGarbageAddresses(t *testing.T) {
	l := tmp(t)
	s := OpenSummary(l.Summary)
	s.CreateNew(true)
	long := "androidx.lifecycle.MutableLiveData@1d9e7abcdefghijkl"
	s.ResetBlockRecords()
	if s.CreditTo(long, 5, 1) || s.CreditTo("", 5, 1) || s.CreditTo("NabcdefghijkLMNPQRSTUVWXYZ12345", -5, 1) {
		t.Fatal("garbage credit accepted")
	}
	_ = s.UpdateChanges()
	for _, r := range s.All() {
		if len(r.Hash) > 0 && r.Hash[0] == 'a' {
			t.Fatalf("garbage account stored: %q", r.Hash)
		}
	}
}

func TestHeadersAndLastString(t *testing.T) {
	l := tmp(t)
	h := OpenHeaders(l.Headers)
	for i := 0; i < 5; i++ {
		h.Add(int64(i), "BH"+string(rune('A'+i)), "SH"+string(rune('A'+i)))
	}
	if h.Height() != 4 || h.LastBlock() != 4 {
		t.Fatal(h.Height())
	}
	raw, _ := os.ReadFile(l.Headers)
	if len(raw) != 5*70 {
		t.Fatal("record size")
	}
	// start = from-100 < 0 gives "" (swallowed seek error).
	if h.LastHeadersString(4) != "" {
		t.Fatal("negative seek must give empty string")
	}
	for i := 5; i < 130; i++ {
		h.Add(int64(i), "B", "S")
	}
	got := h.LastHeadersString(103)
	if got[:6] != "3:B:S " && got[:2] != "3:" {
		t.Fatalf("%q", got[:10])
	}
	if !h.RemoveLast() || h.Height() != 128 {
		t.Fatal("remove last")
	}
}

func TestGVTsGoldenAndRules(t *testing.T) {
	l := tmp(t)
	raw, _ := os.ReadFile("../../testdata/gvts.psk")
	_ = os.WriteFile(l.GVTs, raw, 0o644)
	g := OpenGVTs(l.GVTs)
	if g.Len() != 100 || g.Hash() != crypto.IDHashBytes(raw) {
		t.Fatal("load")
	}
	owner := g.Index(0).Owner
	if g.ChangeOwner(0, "wrong", owner) != 2 || g.ChangeOwner(100, owner, owner) != 2 /* later checks overwrite code 1 (nosogvts.pas:165-168) */ ||
		g.ChangeOwner(0, owner, "bad") != 3 {
		t.Fatal("error codes")
	}
	if g.ChangeOwner(0, owner, g.Index(2).Owner) != 0 {
		t.Fatal("transfer")
	}
	g.Save()
	g.Reload()
	if g.Index(0).Owner != g.Index(2).Owner {
		t.Fatal("persisted")
	}
	// Price: base 70000000000, each missing GVT multiplies by 1.10 with
	// truncating Int64 division (nosogvts.pas:188-198).
	if GVTPrice(40, false) != 70000000000 || GVTPrice(39, false) != 77000000000 ||
		GVTPrice(38, false) != 84700000000 || GVTPrice(38, true) != 71995000000 {
		t.Fatalf("%d %d", GVTPrice(39, false), GVTPrice(38, false))
	}
}

func TestWalletRoundTrip(t *testing.T) {
	l := tmp(t)
	w, existed := OpenWallet(l.Wallet)
	if existed || w.Len() != 1 {
		t.Fatal("new wallet")
	}
	a := w.At(0)
	if !crypto.IsValidHashAddress(a.Hash) || crypto.GetAddressFromPublicKey(a.PublicKey, 0) != a.Hash {
		t.Fatal("generated address")
	}
	raw, _ := os.ReadFile(l.Wallet)
	if len(raw) != types.WalletSize {
		t.Fatalf("wallet size %d", len(raw))
	}
	w2, existed := OpenWallet(l.Wallet)
	if !existed || !bytes.Equal(w2.At(0).Encode(), a.Encode()) {
		t.Fatal("reload")
	}
	if !Exists(l.Wallet + ".bak") {
		t.Fatal("backup copy")
	}
	if w.Insert(a) {
		t.Fatal("duplicate accepted")
	}
}

func TestCFGDefaultAndEdits(t *testing.T) {
	l := tmp(t)
	c := OpenCFG(l.CFG, func() int64 { return 100 }, nil)
	if c.DataStr() != DefaultNosoCFG {
		t.Fatal("default file")
	}
	if c.Param(0) != "NORMAL" || !c.IsSeedNode("204.10.194.22") || c.IsSeedNode("1.1.1.1") {
		t.Fatal("params")
	}
	if c.Hash() != crypto.IDHash(DefaultNosoCFG) {
		t.Fatal("hash")
	}
	if err := c.Add("9.9.9.9;8080", 1); err != nil {
		t.Fatal(err)
	}
	if !c.IsSeedNode("9.9.9.9") {
		t.Fatal("add")
	}
	if err := c.Remove("9.9.9.9;8080", 1); err != nil || c.IsSeedNode("9.9.9.9") {
		t.Fatal("remove")
	}
	if c.DataStr() != DefaultNosoCFG {
		t.Fatalf("round trip differs:\n%s", c.DataStr())
	}
	if c.LastRequest != 105 {
		t.Fatal("LastRequest")
	}
	_ = c.SetData("STOP", 0)
	if c.Param(0) != "STOP" {
		t.Fatal("mode")
	}
}

func TestMNFile(t *testing.T) {
	l := tmp(t)
	m := OpenMNFile(l.Masternodes)
	m.Save("100 1.2.3.4;8080:NfundA:5 5.6.7.8;8080:NfundB:9 9.9.9.9;8080:NfundC:5")
	b, _ := os.ReadFile(l.Masternodes)
	if !bytes.HasSuffix(b, []byte("\r\n")) {
		t.Fatal("CRLF terminator")
	}
	e := m.Entries()
	if len(e) != 3 || e[0].Address != "NfundB" || e[1].Address != "NfundA" || e[2].Address != "NfundC" {
		t.Fatalf("age order %+v", e)
	}
	if m.AgeCount("1.2.3.4", 8080, "NfundA") != ":6" || m.AgeCount("x", 1, "y") != ":1" {
		t.Fatal("age count")
	}
	if m.VerificatorsText() != "5.6.7.8;8080:1.2.3.4;8080:9.9.9.9;8080:" {
		t.Fatal(m.VerificatorsText())
	}
	m2 := OpenMNFile(l.Masternodes)
	if m2.Text() != m.Text() {
		t.Fatal("reload")
	}
}

func TestPSOsRoundTrip(t *testing.T) {
	l := tmp(t)
	p := OpenPSOs(l.PSOs)
	if !Exists(l.PSOs) {
		t.Fatal("file created on first load")
	}
	if !p.AddLocked("NaddrA", 100) || p.AddLocked("NaddrA", 101) {
		t.Fatal("lock")
	}
	p.AddNew(1, "owner", 500, "1:123;2:200")
	p.Save(100)
	raw, _ := os.ReadFile(l.PSOs)
	if len(raw) < 12+40 {
		t.Fatal("size")
	}
	q := OpenPSOs(l.PSOs)
	if q.LockedAt(0).Address != "NaddrA" || q.LockedAt(0).Expire != 100+2016 || len(q.All()) != 1 {
		t.Fatal("reload")
	}
	if PSOValue("2", "1:123;2:200") != "200" {
		t.Fatal("psovalue")
	}
	if q.ClearExpired(100+2016) != 1 || q.LockedCount() != 0 {
		t.Fatal("expiry boundary: expire <= block clears")
	}
}

func TestBlockCodec(t *testing.T) {
	b := &Block{Header: types.BlockHeader{Number: 48010, TrxTotales: 1, AccountMiner: "NM"},
		Orders: []types.Order{{OrderType: "TRFR", OrderID: "OR1"}},
		PosPay: 0, MNsPay: 123, MNsAddrs: []string{"NA", "NB"}}
	raw := b.Encode()
	want := types.HeaderSize + types.OrderSize + 12 + 12 + 2*types.PosAddrSize
	if len(raw) != want {
		t.Fatalf("len %d want %d", len(raw), want)
	}
	got, err := DecodeBlock(raw)
	if err != nil || got.MNsPay != 123 || len(got.MNsAddrs) != 2 || got.MNsAddrs[1] != "NB" {
		t.Fatalf("%v %+v", err, got)
	}
	// A block below 8425 has no tails.
	b0 := &Block{Header: types.BlockHeader{Number: 0}}
	if len(b0.Encode()) != types.HeaderSize {
		t.Fatal("block 0 layout")
	}
	l := tmp(t)
	bs := NewBlocks(l)
	_ = bs.Write(b0)
	_ = bs.Write(b)
	if bs.LastUpdated() != 48010 {
		t.Fatal(bs.LastUpdated())
	}
}

func TestOptionsRoundTrip(t *testing.T) {
	l := tmp(t)
	o := DefaultOptions("0.4.4Ab9")
	o.RPCPort = 9000
	o.RPCPass = "pw"
	o.MNIP = "1.2.3.4"
	o.AutoServer = true
	if err := o.Save(l.AdvOpt); err != nil {
		t.Fatal(err)
	}
	var q Options = DefaultOptions("x")
	if err := q.Load(l.AdvOpt); err != nil {
		t.Fatal(err)
	}
	if q.RPCPort != 9000 || q.RPCPass != "pw" || q.MNIP != "1.2.3.4" || !q.AutoServer || q.LastPoUpdate != "0.4.4Ab9" {
		t.Fatalf("%+v", q)
	}
}

func FuzzDecodeBlock(f *testing.F) {
	b := &Block{Header: types.BlockHeader{Number: 60000, TrxTotales: 1}, Orders: []types.Order{{}}}
	f.Add(b.Encode())
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = DecodeBlock(raw) })
}

func FuzzPSOParse(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		p := &PSOs{}
		p.parse(raw)
	})
}

func TestBlocksDBIndexAndLookup(t *testing.T) {
	l := tmp(t)
	bs := NewBlocks(l)
	o := types.Order{OrderType: "TRFR", OrderID: "ORabc123", Address: "NA", Receiver: "NB", Block: 5}
	_ = bs.Write(&Block{Header: types.BlockHeader{Number: 5, TrxTotales: 1}, Orders: []types.Order{o}})
	d := OpenBlocksDB(l.BlocksDB)
	d.Update(bs)
	if d.Records() != 1 || d.LastBlock() != 5 {
		t.Fatalf("records %d last %d", d.Records(), d.LastBlock())
	}
	if d.BlockFromOrder(bs, "ORabc123") != 5 || d.BlockFromOrder(bs, "ORnothere") != -1 {
		t.Fatal("lookup")
	}
	if ix := DBIndex("ORabc123"); ix < 0 || ix >= 100000 {
		t.Fatal(ix)
	}
	d2 := OpenBlocksDB(l.BlocksDB)
	if len(d2.Blocks("ORabc123")) != 1 {
		t.Fatal("index reload")
	}
}

// FIX(H-10): the encrypted wallet round trips, a wrong passphrase fails, and
// a legacy plaintext wallet is migrated and kept.
func TestH10_WalletEncryptionAndMigration(t *testing.T) {
	l := tmp(t)
	plain, _ := OpenWallet(l.Wallet)
	secret := plain.At(0).PrivateKey
	if secret == "" {
		t.Fatal("no key")
	}
	w, err := OpenWalletEncrypted(l.Wallet, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if w.At(0).PrivateKey != secret || w.Len() != 1 {
		t.Fatal("migration lost the key")
	}
	// migration never destroys the original (see wallet_test.go); the
	// encrypted file must not leak the keys
	if !Exists(l.Wallet) {
		t.Fatal("migration removed the plaintext wallet")
	}
	raw, _ := os.ReadFile(filepath.Join(l.Root, "wallet.enc"))
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(w.At(0).Hash)) {
		t.Fatal("secret or address visible in the encrypted file")
	}
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	w2, err := OpenWalletEncrypted(l.Wallet, []byte("correct horse"))
	if err != nil || w2.At(0).PrivateKey != secret {
		t.Fatalf("reopen: %v", err)
	}
	// a tampered file is detected (AEAD)
	raw[len(raw)-3] ^= 1
	_ = os.WriteFile(filepath.Join(l.Root, "wallet.enc"), raw, 0o600)
	if _, err := OpenWalletEncrypted(l.Wallet, []byte("correct horse")); err == nil {
		t.Fatal("tampered wallet accepted")
	}
	if st, _ := os.Stat(filepath.Join(l.Root, "wallet.enc")); st.Mode().Perm() != 0o600 {
		t.Fatal("wallet.enc must be 0600")
	}
}

// FIX(M-09): counts that exceed the file are refused before anything is read.
func TestM09_PSOCountsChecked(t *testing.T) {
	// header claims 2 billion locked masternodes in a 12 byte file
	hdr := []byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0}
	if ValidPSOFile(hdr) {
		t.Fatal("hostile counts accepted")
	}
	neg := []byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}
	if ValidPSOFile(neg) {
		t.Fatal("negative count accepted")
	}
	ok := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !ValidPSOFile(ok) {
		t.Fatal("empty file refused")
	}
}

// FIX(M-12): the atomic writer leaves no temporary file and reports errors.
func TestM12_AtomicWrite(t *testing.T) {
	l := tmp(t)
	p := filepath.Join(l.Root, "x.bin")
	if err := writeFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" || Exists(p+".tmp") {
		t.Fatal("atomic write left debris")
	}
	if err := writeFileAtomic(filepath.Join(l.Root, "no", "such", "dir", "f"), []byte("x")); err == nil {
		t.Fatal("write error swallowed")
	}
}

// FIX(M-16): the committed fixtures are the ones the tests were written for.
func TestM16_FixtureChecksums(t *testing.T) {
	want := map[string]string{
		"59238.psk": "", "gvts.psk": "", "defseeds.nos": "", "1mb.dat": "",
	}
	for name := range want {
		b, err := os.ReadFile("../../testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		want[name] = hex.EncodeToString(sum[:])
	}
	// Recorded when the fixtures were copied from the original repository.
	pinned := map[string]string{
		"59238.psk":    fixtureSHA["59238.psk"],
		"gvts.psk":     fixtureSHA["gvts.psk"],
		"defseeds.nos": fixtureSHA["defseeds.nos"],
		"1mb.dat":      fixtureSHA["1mb.dat"],
	}
	for k, v := range pinned {
		if want[k] != v {
			t.Fatalf("%s changed: %s", k, want[k])
		}
	}
}
