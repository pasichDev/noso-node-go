package node

import (
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// F-13: a journal that does not fit the chain on disk is discarded; it cannot
// cut a longer chain back to the tip it names.
func TestPlantedJournalCannotCutTheChain(t *testing.T) {
	b := newBed(t, 1)
	a := b.nodes[0]
	for i := 0; i < 4; i++ {
		b.build(a)
	}
	tip, hash := a.MyLastBlock(), a.MyLastBlockHash()
	// a real snapshot (so the file passes the old checks) and a journal that
	// claims the change began at block 2
	if err := a.snapshot("plant"); err != nil {
		t.Fatal(err)
	}
	for name, j := range map[string]journal{
		"no anchor":    {Restore: "plant", Last: 2},
		"wrong tip":    {Restore: "plant", Last: 2, Anchor: 2, AnchorHash: crypto.IDHashFile(a.Lay.BlockFile(2))},
		"wrong anchor": {Restore: "plant", Last: tip, Anchor: tip, AnchorHash: "0123456789abcdef0123456789abcdef"},
		"stage 2 fork": {Restore: "plant", Last: tip, Start: 3, Count: 1, Anchor: 2, AnchorHash: "0123456789abcdef0123456789abcdef"},
	} {
		if err := a.writeJournal(j); err != nil {
			t.Fatal(err)
		}
		g, err := New(a.Lay.Root, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if g.MyLastBlock() != tip || g.MyLastBlockHash() != hash {
			t.Fatalf("%s: the chain was cut to %d", name, g.MyLastBlock())
		}
		if err := consistent(g); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
