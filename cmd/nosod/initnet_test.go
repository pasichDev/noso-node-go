package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

func runInit(t *testing.T, args ...string) (int, string) {
	t.Helper()
	t.Setenv("NOSO_WALLET_PASSPHRASE", "correct horse battery")
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }() // test cleanup
	errf, err := os.CreateTemp(t.TempDir(), "err")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = errf.Close() }() // test cleanup
	rc := initNetwork(args, out, errf)
	a, _ := os.ReadFile(out.Name())
	b, _ := os.ReadFile(errf.Name())
	return rc, string(a) + string(b)
}

func nodePorts(t *testing.T, dir string, i int) (peer, rpc int) {
	t.Helper()
	var o storage.Options
	if err := o.Load(filepath.Join(dir, fmt.Sprintf("node%d", i), "advopt.txt")); err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(o.MNPort)
	return p, o.RPCPort
}

// The default ports of any node count must not overlap: a peer port that is
// another node's RPC port leaves that node without a server or without RPC,
// and nothing says so (final operator walk, step 2).
func TestInitNetworkDefaultPortsDoNotOverlap(t *testing.T) {
	for _, nodes := range []int{1, 3, 5, 8} {
		dir := t.TempDir()
		rc, out := runInit(t, "-dir", dir, "-nodes", strconv.Itoa(nodes), "-proposers", "1")
		if rc != 0 {
			t.Fatalf("%d nodes: rc %d: %s", nodes, rc, out)
		}
		used := map[int]string{}
		for i := 1; i <= nodes; i++ {
			peer, rpc := nodePorts(t, dir, i)
			for _, c := range []struct {
				port int
				what string
			}{{peer, "peer"}, {rpc, "rpc"}} {
				if prev, dup := used[c.port]; dup {
					t.Fatalf("%d nodes: node%d %s port %d is also %s", nodes, i, c.what, c.port, prev)
				}
				used[c.port] = fmt.Sprintf("node%d %s", i, c.what)
			}
		}
	}
}

// Ports that do overlap, or leave the valid range, are refused before
// anything is written.
func TestInitNetworkRefusesOverlappingPorts(t *testing.T) {
	cases := [][]string{
		{"-nodes", "4", "-base-port", "18080", "-rpc-base-port", "18082"}, // rpc 18082,83 are peers 3,4
		{"-nodes", "3", "-base-port", "20000", "-rpc-base-port", "20000"},
		{"-nodes", "4", "-base-port", "65534"},
		{"-nodes", "2", "-base-port", "0"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		rc, out := runInit(t, append([]string{"-dir", dir}, c...)...)
		if rc == 0 {
			t.Errorf("%v: accepted", c)
			continue
		}
		if !strings.Contains(out, "port") {
			t.Errorf("%v: refusal does not name the ports: %q", c, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "node1")); err == nil {
			t.Errorf("%v: refused, but a data directory was written", c)
		}
	}
}

// -host really is where the P2P listener binds, and the default is loopback.
func TestInitNetworkWritesBindAddress(t *testing.T) {
	dir := t.TempDir()
	if rc, out := runInit(t, "-dir", dir, "-nodes", "2", "-proposers", "1"); rc != 0 {
		t.Fatal(out)
	}
	if got := readBind(filepath.Join(dir, "node1")); got != "127.0.0.1" {
		t.Fatalf("default bind %q, want loopback", got)
	}
	dir2 := t.TempDir()
	if rc, out := runInit(t, "-dir", dir2, "-nodes", "2", "-proposers", "1", "-host", "127.0.0.2"); rc != 0 {
		t.Fatal(out)
	}
	if got := readBind(filepath.Join(dir2, "node2")); got != "127.0.0.2" {
		t.Fatalf("bind %q, want the -host value", got)
	}
}

// Every node gets the same configuration, seed list included: the consensus
// hash contains a hash of it, so lists that differ can never agree.
func TestInitNetworkSeedListsAreIdentical(t *testing.T) {
	dir := t.TempDir()
	if rc, out := runInit(t, "-dir", dir, "-nodes", "4", "-proposers", "3"); rc != 0 {
		t.Fatal(out)
	}
	var first string
	for i := 1; i <= 4; i++ {
		raw, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d", i), "NOSODATA", "nosocfg.psk"))
		if err != nil {
			raw, err = os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d", i), "nosocfg.psk"))
		}
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			first = string(raw)
		} else if string(raw) != first {
			t.Fatalf("node%d configuration differs from node1:\n%s\n%s", i, raw, first)
		}
	}
	if strings.Count(first, "127.0.0.1;") != 4 {
		t.Fatalf("seed list does not name all four nodes: %s", first)
	}
}

// The output of `nosocli pubkey` ("ADDRESS KEY") can be used as the proposers
// file as it is.
func TestJoinAcceptsPubkeyOutput(t *testing.T) {
	kp := crypto.GenerateKeyPair()
	file := filepath.Join(t.TempDir(), "proposers.txt")
	line := crypto.GetAddressFromPublicKey(kp.PublicKey, 0) + " " + kp.PublicKey + "\n"
	if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(t.TempDir(), "node")
	rc, out := runInit(t, "-data", data, "-proposer-keys", file, "-seed", "127.0.0.1:18080", "-bind", "127.0.0.1")
	if rc != 0 {
		t.Fatalf("rc %d: %s", rc, out)
	}
	raw, err := os.ReadFile(filepath.Join(data, "proposers.txt"))
	if err != nil || !strings.Contains(string(raw), kp.PublicKey) {
		t.Fatalf("proposers.txt: %v %q", err, raw)
	}
	if readBind(data) != "127.0.0.1" {
		t.Fatal("bind not written")
	}
}

// init-network writes one network file, the same on every node, with a random
// chain id; the loopback default sets local_masternodes, a public host does not.
func TestInitNetworkWritesNetworkFile(t *testing.T) {
	read := func(dir string, i int) string {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d", i), "network.txt"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	a, b := t.TempDir(), t.TempDir()
	if rc, out := runInit(t, "-dir", a, "-nodes", "2", "-proposers", "1"); rc != 0 {
		t.Fatalf("rc %d: %s", rc, out)
	}
	if rc, out := runInit(t, "-dir", b, "-nodes", "2", "-proposers", "1", "-host", "203.0.113.7", "-bind", "127.0.0.1"); rc != 0 {
		t.Fatalf("rc %d: %s", rc, out)
	}
	if read(a, 1) != read(a, 2) || read(b, 1) != read(b, 2) {
		t.Fatal("nodes of one network hold different network files")
	}
	if read(a, 1) == read(b, 1) {
		t.Fatal("two networks share one network file")
	}
	if !strings.Contains(read(a, 1), "local_masternodes true") {
		t.Fatal("a loopback network must allow local masternodes")
	}
	if !strings.Contains(read(b, 1), "local_masternodes false") {
		t.Fatal("a non-loopback host must not allow local masternodes")
	}
}
