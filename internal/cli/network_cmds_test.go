package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
)

func newDisp(t *testing.T, withEngine bool) *Dispatcher {
	n, err := node.New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var e *network.Engine
	if withEngine {
		e = network.NewEngine(n)
	}
	return New(n, e, nil)
}

// pubkey prints the public key and never the private one.
func TestPubKeyHasNoPrivateKey(t *testing.T) {
	d := newDisp(t, false)
	out := strings.Join(d.Run("pubkey"), "\n")
	w := d.N.Wallet.At(0)
	if !strings.Contains(out, w.PublicKey) || !strings.Contains(out, w.Hash) || strings.Contains(out, w.PrivateKey) {
		t.Fatalf("pubkey printed %q", out)
	}
}

// M7: addnode and delnode reach the running engine at once, and `clearcfg 1`
// followed by `addnode` leaves exactly one seed.
func TestAddNodeReachesEngine(t *testing.T) {
	d := newDisp(t, true)
	d.Run("clearcfg 1")
	d.Run("addnode 10.0.0.1;8080")
	if l := d.E.NodesList(); len(l) != 1 || l[0] != "10.0.0.1:8080" {
		t.Fatalf("nodes: %v", l)
	}
	d.Run("delnode 10.0.0.1;8080")
	if l := d.E.NodesList(); len(l) != 0 {
		t.Fatalf("nodes after delnode: %v", l)
	}
}

// The default configuration holds no seed at all.
func TestNoDefaultSeeds(t *testing.T) {
	d := newDisp(t, true)
	if l := d.E.NodesList(); len(l) != 0 {
		t.Fatalf("a fresh node knows %v", l)
	}
}

func TestMasternodeCommands(t *testing.T) {
	d := newDisp(t, false)
	w := d.N.Wallet.At(0)
	out := strings.Join(d.Run("mnset 8.8.4.4 8080 "+w.Hash+" "+w.Hash), "\n")
	if !strings.Contains(out, "Masternode set") || d.N.Options().MNIP != "8.8.4.4" {
		t.Fatalf("mnset: %q", out)
	}
	if o := strings.Join(d.Run("mnset 8.8.4.4 8080 "+w.Hash+" Nnotinwallet"), "\n"); strings.Contains(o, "Masternode set") {
		t.Fatalf("mnset accepted a foreign sign address: %q", o)
	}
	del := strings.Fields(strings.Join(d.Run("mndelegate "+w.Hash+" "+w.Hash), "\n"))
	if len(del) != 2 || strings.Contains(strings.Join(del, " "), w.PrivateKey) {
		t.Fatalf("mndelegate: %v", del)
	}
	if o := strings.Join(d.Run("mnsetdelegation "+del[0]+" "+del[1]), "\n"); !strings.Contains(o, "stored") {
		t.Fatalf("mnsetdelegation: %q", o)
	}
	if o := strings.Join(d.Run("mnsetdelegation "+del[0]+" AAAA"), "\n"); strings.Contains(o, "stored") {
		t.Fatalf("a bad delegation was stored: %q", o)
	}
}

// M5: restoreblockchain asks for a confirmation and, in a program that
// cannot restart the node, refuses to delete under a running one.
func TestRestoreChainNeedsConfirmation(t *testing.T) {
	d := newDisp(t, true)
	if o := strings.Join(d.Run("restoreblockchain"), "\n"); !strings.Contains(o, "confirm") {
		t.Fatalf("no confirmation asked: %q", o)
	}
	if o := strings.Join(d.Run("restoreblockchain confirm"), "\n"); !strings.Contains(o, "cannot restart") {
		t.Fatalf("a program that cannot restart deleted the chain: %q", o)
	}
	if d.N.Blocks.Header(0).Number != 0 || d.N.Lay.BlockFile(0) == "" {
		t.Fatal("blocks gone")
	}
}

func TestDenyPeerCommand(t *testing.T) {
	d := newDisp(t, true)
	d.Run("denypeer 127.0.0.1:9999")
	if got := d.E.DeniedPeers(); len(got) != 1 || got[0] != "127.0.0.1:9999" {
		t.Fatalf("denied %v", got)
	}
	d.Run("allowpeer all")
	if len(d.E.DeniedPeers()) != 0 {
		t.Fatal("allowpeer all")
	}
}
