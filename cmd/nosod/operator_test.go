package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// The README, followed as a new operator with the real binaries: init-network
// with its default ports, four nodes (every listener bound to loopback with
// -bind), repeated payments from a follower that never builds a block, the
// balances on every node, a restart, and the failures an operator meets
// (a typo in -data, an unknown command, a refused order) answering with a
// non-zero exit code. Only the chain clock is faster than real time.

const opPass = "correct horse battery"

func runBin(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NOSO_WALLET_PASSPHRASE="+opPass)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return out.String(), rc
}

func portsFree(ports ...int) bool {
	for _, p := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return false
		}
		_ = l.Close() // test cleanup
	}
	return true
}

func TestOperatorWalkWithDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("starts four daemons")
	}
	// init-network's defaults for four nodes: peers 18080..83, RPC 18084..87
	var def []int
	for p := 18080; p <= 18087; p++ {
		def = append(def, p)
	}
	if !portsFree(def...) {
		t.Skip("the default ports 18080-18087 are in use on this machine")
	}
	root := t.TempDir()
	nosod, nosocli := filepath.Join(root, "nosod"), filepath.Join(root, "nosocli")
	for bin, pkg := range map[string]string{nosod: ".", nosocli: "../nosocli"} {
		if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", pkg, err, out)
		}
	}
	netDir := filepath.Join(root, "net")

	// 1. nosod without a passphrase refuses and leaves nothing behind
	stray := filepath.Join(root, "nopass")
	cmd := exec.Command(nosod, "-data", stray, "-no-ntp", "-bind", "127.0.0.1")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "passphrase") {
		t.Fatalf("nosod without a passphrase: %v %s", err, out)
	}
	if _, err := os.Stat(stray); err == nil {
		t.Fatal("the refused start left a data directory behind")
	}

	// 2. init-network with its defaults (only the clock is sped up)
	if out, rc := runBin(t, nosod, "init-network", "-dir", netDir, "-clock-scale", strconv.Itoa(netScale)); rc != 0 {
		t.Fatalf("init-network: %s", out)
	}
	var ps []*proc
	for i := 0; i < 4; i++ {
		ps = append(ps, &proc{dir: filepath.Join(netDir, fmt.Sprintf("node%d", i+1)), port: 18080 + i, rpc: 18084 + i})
	}
	defer func() {
		for _, p := range ps {
			p.stop()
		}
	}()
	for _, p := range ps {
		p.start(t, nosod)
	}
	cli := func(i int, args ...string) (string, int) {
		return runBin(t, nosocli, append([]string{"-data", ps[i].dir}, args...)...)
	}
	var diag func() string
	wait := func(what string, d time.Duration, f func() bool) {
		t.Helper()
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			if f() {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
		for i, p := range ps {
			if raw, err := os.ReadFile(p.dir + ".log"); err == nil {
				if len(raw) > 2500 {
					raw = raw[len(raw)-2500:]
				}
				t.Logf("--- node%d log tail:\n%s", i+1, raw)
			}
		}
		if diag != nil {
			t.Logf("state: %s", diag())
		}
		t.Fatalf("timeout waiting for %s", what)
	}

	// 3. every default port is really bound: four peer listeners, four RPC servers
	wait("all eight default ports to listen", 60*time.Second, func() bool {
		for _, p := range def {
			if portsFree(p) {
				return false
			}
		}
		return true
	})
	for _, p := range ps {
		if !strings.Contains(p.rpcCall(t, "RPCToken", "test"), "testok") {
			t.Fatalf("RPC of %s does not answer", p.dir)
		}
	}

	// 4. blocks on all nodes, the seeds agree (consensus), the RPC overview works
	all := []int{0, 1, 2, 3}
	wait("blocks on all four nodes", 120*time.Second, func() bool {
		a, h := ps[0].tip()
		for _, i := range all {
			n, hh := ps[i].tip()
			if n < 6 || n != a || hh != h {
				return false
			}
		}
		return true
	})
	wait("the consensus and isallsynced 0 on the follower", 90*time.Second, func() bool {
		out, rc := cli(3, "isallsynced")
		return rc == 0 && strings.TrimSpace(out) == "0"
	})
	if info := ps[3].rpcCall(t, "RPCToken", "getmainnetinfo"); strings.Contains(info, "error") || !strings.Contains(info, "lastblock") {
		t.Fatalf("getmainnetinfo: %s", info)
	}

	// 5. exit codes and typos
	if out, rc := cli(3, "nosuchcommand"); rc == 0 {
		t.Fatalf("an unknown command exited 0: %s", out)
	}
	if out, rc := runBin(t, nosocli, "-data", filepath.Join(root, "typo"), "balance"); rc == 0 || fileExists(filepath.Join(root, "typo")) {
		t.Fatalf("a typo in -data: rc %d, created=%v: %s", rc, fileExists(filepath.Join(root, "typo")), out)
	}
	if out, rc := cli(3, "sendto", "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df", "1.123456789"); rc == 0 {
		t.Fatalf("an amount with 9 decimals was accepted: %s", out)
	}

	// 6. the follower is paid by a proposer, then pays three times in a row
	pk, rc := cli(3, "pubkey")
	m := regexp.MustCompile(`^(N\w+) `).FindStringSubmatch(pk)
	if rc != 0 || m == nil {
		t.Fatalf("pubkey: %d %q", rc, pk)
	}
	follower := m[1]
	send := func(from int, dest, amount string) {
		t.Helper()
		var out string
		for try := 0; try < 80; try++ { // ERROR 20: the node is a moment behind a new block
			var rc int
			out, rc = cli(from, "sendto", dest, amount, "walk")
			if rc == 0 && strings.Contains(out, "Order ID") {
				return
			}
			time.Sleep(400 * time.Millisecond)
		}
		t.Fatalf("sendto %s %s from node%d never went through: %s", dest, amount, from+1, out)
	}
	bal := func(i int, addr string) string {
		return ps[i].rpcCall(t, "RPCToken", "getaddressbalance", addr)
	}
	wait("a funded proposer", 120*time.Second, func() bool {
		out, _ := cli(0, "balance")
		return !strings.HasPrefix(strings.TrimSpace(out), "0.00000000")
	})
	send(0, follower, "5")
	wait("the follower to hold 5 NOSO on every node", 120*time.Second, func() bool {
		for i := range ps {
			if !strings.Contains(bal(i, follower), `"balance":500000000`) {
				return false
			}
		}
		return true
	})
	dest := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0) // an address nobody else pays
	diag = func() string {
		var b strings.Builder
		for i := range ps {
			pend, _ := cli(i, "pending")
			fmt.Fprintf(&b, "\nnode%d dest=%s follower=%s pending=%q", i+1, bal(i, dest), bal(i, follower), pend)
		}
		return b.String()
	}
	for k := 1; k <= 3; k++ {
		send(3, dest, "1.5")
		want := fmt.Sprintf(`"balance":%d`, k*150000000)
		wait(fmt.Sprintf("payment %d to show on every node", k), 120*time.Second, func() bool {
			for i := range ps {
				if !strings.Contains(bal(i, dest), want) {
					return false
				}
			}
			return true
		})
	}
	// the follower's own pool is not left holding mined orders
	wait("the follower's pool to empty", 60*time.Second, func() bool {
		return !strings.Contains(ps[3].rpcCall(t, "RPCToken", "getpendingorders"), ",TRFR,")
	})
	// 5 NOSO in, three payments of 1.5 and the minimum fee of 0.01 each out
	if left := `"balance":47000000,`; !strings.Contains(bal(3, follower), left) {
		t.Fatalf("follower balance %s, want %s", bal(3, follower), left)
	}

	// 7. a restart through the control socket: the node comes back and catches up
	h, _ := ps[1].tip()
	if out, rc := cli(1, "restart"); rc != 0 {
		t.Fatalf("restart: %s", out)
	}
	wait("the restarted node to catch up", 150*time.Second, func() bool {
		n0, h0 := ps[0].tip()
		n1, h1 := ps[1].tip()
		return n1 > h && n1 == n0 && h1 == h0
	})
	if !strings.Contains(bal(1, dest), `"balance":450000000`) {
		t.Fatalf("balance after the restart: %s", bal(1, dest))
	}

}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
