package node

import (
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// F-20: the shape of a report is judged without any signature check, so a
// caller can refuse it on stake first; the signatures are checked by SigOK.
func TestReportShapeIsSeparateFromItsSignature(t *testing.T) {
	b := newBed(t, 1)
	n := b.nodes[0]
	k := crypto.GenerateKeyPair()
	addr := crypto.GetAddressFromPublicKey(k.PublicKey, 0)
	m := MNode{IP: "8.8.8.8", Port: 8080, Sign: addr, Fund: addr, First: 1, Last: 1, Pub: k.PublicKey, Sig: "garbage"}
	m.Hash = crypto.IDHash(m.IP + "8080" + m.Sign + m.Fund)
	line := "$MNREPO " + StringFromMN(m)
	got, ok := n.ParseMNShape(line)
	if !ok || got.SigOK() {
		t.Fatalf("shape ok=%v, signature ok=%v; want a good shape with a bad signature", ok, got.SigOK())
	}
	if _, ok := ParseMNode(line); ok {
		t.Fatal("a report with a bad signature was parsed")
	}
	m.Sig = crypto.SignCanonical(k.PrivateKey, "MNREPORT1", mnReportFields(m)...)
	if got, ok := n.ParseMNShape("$MNREPO " + StringFromMN(m)); !ok || !got.SigOK() {
		t.Fatal("a good report was refused")
	}
}
