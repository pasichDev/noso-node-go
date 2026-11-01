package node

import (
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// F-9: what a peer can make the sign key sign is tight. A synced node answers
// MNVER with a fresh-looking nonce under a non-proposer key; it never signs
// for a proposer key, and the nonce has the exact form of a challenge.
func TestMNVERNeverSignsWithAProposerKey(t *testing.T) {
	b := newBed(t, 1)
	n := b.nodes[0]
	b.build(n)
	n.Consensus = func(i int) string {
		switch i {
		case 2:
			return codec.IntToStr(n.MyLastBlock())
		case 10:
			return n.MyLastBlockHash()
		case 17:
			return codec.Copy(n.Summary.Hash(), 1, 5)
		case 5:
			return codec.Copy(n.Headers.Hash(), 1, 5)
		}
		return ""
	}
	prop := n.Wallet.At(0)
	other, err := n.Wallet.NewAddress()
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "0123456789abcdef01234567"
	use := func(sign string) string {
		n.UpdateOptions(func(o *StorageOptions) { o.MNSign, o.MNFunds = sign, prop.Hash })
		return n.VerificationLine(nonce)
	}
	if got := use(other.Hash); !strings.HasPrefix(got, "True ") {
		t.Fatalf("a non-proposer sign key does not answer: %q", got)
	}
	if got := use(prop.Hash); got != "False" {
		t.Fatalf("the proposer key signed for a peer: %q", got)
	}
	if !n.MNSignIsProposerKey() {
		t.Fatal("MNSignIsProposerKey is false for the proposer key")
	}
	use(other.Hash)
	for _, bad := range []string{"", "short", "0123456789ABCDEF0123", "0123456789abcdef 0123", "0123456789abcdeg", strings.Repeat("a", 65), "x\n0123456789abcdef"} {
		if got := n.VerificationLine(bad); got != "False" {
			t.Errorf("nonce %q was signed: %q", bad, got)
		}
	}
}
