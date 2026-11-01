package network

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/node"
)

// Masternodes are listed on a network of engines whose seeds agree. A
// masternode needs a public-looking address (the node refuses loopback and
// private ranges for its reports, since it dials the address a report names),
// so the test gives node 0 a public-looking address (never dialled as such) and makes every dial to
// that range land on loopback: nothing ever leaves this machine.
func TestMasternodeIsListedOnEveryNode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a few block periods on a fast chain clock")
	}
	d := newDevnet(t, 4, 3, 100)
	defer d.stopAll()
	for _, e := range d.eng {
		e.Dial = func(addr string, to time.Duration) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			if strings.HasPrefix(host, "9.9.9.") {
				host = "127.0.0.1"
			}
			return net.DialTimeout("tcp", net.JoinHostPort(host, port), to)
		}
	}
	w := d.nodes[0].Wallet.At(0)
	d.nodes[0].UpdateOptions(func(o *node.StorageOptions) {
		o.MNIP = "9.9.9.1"
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
