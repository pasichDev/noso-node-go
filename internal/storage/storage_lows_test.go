package storage

import (
	"os"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Item 17: String[32] truncation of a new GVT owner happens at the assignment
// (nosogvts.pas:172).
func TestGVTOwnerTruncatedAtOnce(t *testing.T) {
	body := strings.Repeat("A", 32)
	addr := "N" + body + crypto.BMDecTo58(crypto.BMB58resumen(body))
	if len(addr) <= 32 || !crypto.IsValidHashAddress(addr) {
		t.Skipf("could not build a long valid address: %q", addr)
	}
	l := tmp(t)
	raw, _ := os.ReadFile("../../testdata/gvts.psk")
	if err := os.WriteFile(l.GVTs, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	g := OpenGVTs(l.GVTs)
	if res := g.ChangeOwner(0, g.Index(0).Owner, addr); res != 0 {
		t.Fatalf("change refused (%d)", res)
	}
	if got := g.Index(0).Owner; got != addr[:32] {
		t.Fatalf("owner %q kept %d characters", got, len(got))
	}
}

// Item 16: AddRecordToHeaders seeks to filesize(file), which counts whole
// records, so a partial last record is overwritten (nosoheaders.pas:110).
func TestHeadersAddOverwritesPartialRecord(t *testing.T) {
	l := tmp(t)
	h := OpenHeaders(l.Headers)
	h.Create()
	if !h.Add(1, "B1", "S1") {
		t.Fatal("add")
	}
	f, _ := os.OpenFile(l.Headers, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.Write([]byte("junk!")) // 75 bytes now
	f.Close()
	if !h.Add(2, "B2", "S2") {
		t.Fatal("add 2")
	}
	st, _ := os.Stat(l.Headers)
	if st.Size() != 2*types.ResumenSize {
		t.Fatalf("size %d, Pascal writes at offset 70", st.Size())
	}
	all := h.All()
	if len(all) != 2 || all[1].Block != 2 || all[1].BlockHash != "B2" {
		t.Fatalf("%+v", all)
	}
}

// Item 8: the case folding of StringReplace is ASCII only, so non-ASCII text
// cannot panic by changing its byte length.
func TestReplaceFoldNonASCII(t *testing.T) {
	if got := replaceFold("İİİİ:abc:", "c:"); got != "İİİİ:ab" {
		t.Fatalf("%q", got)
	}
	if got := replaceFold("Ab:AB:ab:", "ab:"); got != "" {
		t.Fatalf("%q", got)
	}
	l := tmp(t)
	c := OpenCFG(l.CFG, func() int64 { return 1 }, nil)
	if err := c.SetData("İİİİ:abc:", 9); err == nil {
		_ = c.Remove("c:", 9) // must not panic
	}
}

// Item 14: advopt booleans are parsed by TryStrToBool (numbers included).
func TestAdvoptBoolAcceptsNumbers(t *testing.T) {
	l := tmp(t)
	if err := os.WriteFile(l.AdvOpt, []byte("HideEmpty 2\nMultiSend 0.5\nNoGUI 0\nBlocksDB False\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := DefaultOptions("x")
	if err := o.Load(l.AdvOpt); err != nil {
		t.Fatal(err)
	}
	if !o.HideEmpty || !o.MultiSend || o.NoGUI || o.BlocksDB {
		t.Fatalf("%+v", o)
	}
}

// Item 6: alias uniqueness must see an alias set by a CUSTOM order, in the
// current block and in the committed file, although the alias index (Pascal
// COMPAT) does not list it until the index is rebuilt.
func TestAliasTakenSeesFreshCustomization(t *testing.T) {
	l := tmp(t)
	s := OpenSummary(l.Summary)
	s.CreateNew(false)
	a := "NaddressAAAAAAAAAAAAAAAAAAAAA"
	b := "NaddressBBBBBBBBBBBBBBBBBBBBB"
	s.ResetBlockRecords()
	s.CreditTo(a, 100000000, 1)
	s.CreditTo(b, 100000000, 1)
	if err := s.UpdateChanges(); err != nil {
		t.Fatal(err)
	}
	s.ResetBlockRecords()
	if s.AliasTaken("aliasfoo") {
		t.Fatal("alias taken before anyone set it")
	}
	if !s.CustomizationValid(a, "aliasfoo", 2, false, 25000) {
		t.Fatal("customization refused")
	}
	if !s.AliasTaken("aliasfoo") {
		t.Fatal("alias set in this block is not seen")
	}
	if err := s.UpdateChanges(); err != nil {
		t.Fatal(err)
	}
	s.ResetBlockRecords()
	if slot, _ := s.GetIndexPosition("aliasfoo", true); slot >= 0 {
		t.Log("alias index already lists the alias (not required)")
	}
	if !s.AliasTaken("aliasfoo") {
		t.Fatal("committed alias is not seen: a second address could claim it")
	}
	// a forced change (replay) frees the old alias
	s.CustomizationValid(a, "aliasbar", 3, true, 0)
	if s.AliasTaken("aliasfoo") || !s.AliasTaken("aliasbar") {
		t.Fatal("changed alias still taken / new not taken")
	}
	_ = b
}

// The genesis GVTs are a function of nothing but the owner: the same bytes on
// every node and after every replay.
func TestGVTSeedIsDeterministic(t *testing.T) {
	a, b := OpenGVTs(tmp(t).GVTs), OpenGVTs(tmp(t).GVTs)
	a.Seed("N3DthVsfEUtqrgWFHTEB6F88xLkT3Df")
	b.Seed("N3DthVsfEUtqrgWFHTEB6F88xLkT3Df")
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if a.Len() != 100 || a.Hash() != b.Hash() {
		t.Fatalf("%d records, %s/%s", a.Len(), a.Hash(), b.Hash())
	}
	a.Reload()
	if a.Len() != 100 || a.Index(99).Number != "99" || a.Index(0).Owner != "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df" {
		t.Fatalf("reload: %+v", a.Index(99))
	}
}

// AddBlock writes one block's records at once; RollbackTo takes them out; a
// reorganised branch leaves no record behind.
func TestBlocksDBAddBlockAndRollback(t *testing.T) {
	l := tmp(t)
	d := OpenBlocksDB(l.BlocksDB)
	o := func(id string, blk int32) types.Order {
		return types.Order{OrderType: "TRFR", OrderID: id, Address: "NA", Receiver: "NB", Block: blk}
	}
	if err := d.AddBlock(3, []types.Order{o("ORa", 3), o("ORb", 3)}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddBlock(4, []types.Order{o("ORc", 4)}); err != nil {
		t.Fatal(err)
	}
	if d.Records() != 3 || d.LastBlock() != 4 {
		t.Fatalf("records %d last %d", d.Records(), d.LastBlock())
	}
	if err := d.RollbackTo(3); err != nil {
		t.Fatal(err)
	}
	if d.Records() != 2 || d.LastBlock() != 3 || len(d.Blocks("ORc")) != 0 || len(d.Blocks("ORa")) != 1 {
		t.Fatalf("after rollback: records %d last %d", d.Records(), d.LastBlock())
	}
}
