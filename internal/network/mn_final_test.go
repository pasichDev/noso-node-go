package network

import (
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/node"
)

// Masternodes are listed on a network of engines whose seeds agree. The
// network file sets local_masternodes, so the masternode is announced on
// 127.0.0.1 itself and nothing has to pretend to be a public address.
func TestMasternodeIsListedOnEveryNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a few block periods on a fast chain clock")
	}
	cfg, err := node.NewNetworkConfig(true)
	if err != nil {
		t.Fatal(err)
	}
	d := newDevnetWith(t, 4, 3, 100, &cfg)
	defer d.stopAll()
	w := d.nodes[0].Wallet.At(0)
	d.nodes[0].UpdateOptions(func(o *node.StorageOptions) {
		o.MNIP = "127.0.0.1"
		o.MNFunds = w.Hash
		o.MNSign = w.Hash
	})
	d.start(0, 1, 2, 3)
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		listed := 0
		for _, nd := range d.nodes {
			if nd.MNsListLen() >= 1 {
				listed++
			}
		}
		if listed == len(d.nodes) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	var st []string
	for i, nd := range d.nodes {
		st = append(st, strings.TrimSpace(strings.Join([]string{"n", string(rune('0' + i)), ":", itoa(nd.MNsListLen()), "synced", itoa(nd.IsAllSynced())}, " ")))
	}
	t.Fatalf("masternode never listed on every node: %v | %s", st, d.status())
}

func itoa(v int) string { return string(rune('0' + v%10)) }
