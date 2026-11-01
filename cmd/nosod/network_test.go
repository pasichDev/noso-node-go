package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/control"
)

// The whole story, from the documents, with real processes: `nosod
// init-network` makes a network of four nodes on 127.0.0.1 (three
// proposers), four `nosod` processes run it on a chain clock 200 times
// faster than real time, an order placed over JSON-RPC reaches every node, a
// node is restarted, the network is cut into two halves that both go on
// building and healed again, and all four converge on one chain of 50 or more
// blocks. Nothing leaves loopback: every node's seed list is written by
// init-network before the first start, and NTP is off.

const netScale = 200

type proc struct {
	dir  string
	cmd  *exec.Cmd
	log  *os.File
	port int
	rpc  int
}

func freePorts(t *testing.T, n int) int {
	t.Helper()
	for base := 31000; base < 60000; base += 37 {
		var ls []net.Listener
		ok := true
		for i := 0; i < n*2 && ok; i++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			ls = append(ls, l)
		}
		for _, l := range ls {
			l.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port range")
	return 0
}

func (p *proc) start(t *testing.T, bin string) {
	t.Helper()
	f, err := os.OpenFile(p.dir+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	p.log = f
	p.cmd = exec.Command(bin, "-data", p.dir, "-no-ntp")
	p.cmd.Env = append(os.Environ(), "NOSO_WALLET_PASSPHRASE=correct horse battery")
	p.cmd.Stdout, p.cmd.Stderr = f, f
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
}

func (p *proc) stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	p.log.Close()
	p.cmd = nil
}

// tip returns the number and identity hash of the newest block file.
func (p *proc) tip() (int, string) {
	ents, _ := os.ReadDir(filepath.Join(p.dir, "BLOCKS"))
	best := -1
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".blk")); err == nil && strings.HasSuffix(e.Name(), ".blk") && n > best {
			best = n
		}
	}
	if best < 0 {
		return -1, ""
	}
	raw, err := os.ReadFile(filepath.Join(p.dir, "BLOCKS", fmt.Sprintf("%d.blk", best)))
	if err != nil {
		return -1, ""
	}
	h := sha256.Sum256(raw)
	return best, hex.EncodeToString(h[:4])
}

func (p *proc) token(name string) string {
	raw, _ := os.ReadFile(filepath.Join(p.dir, "advopt.txt"))
	for _, l := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == name {
			return f[1]
		}
	}
	return ""
}

func (p *proc) rpcCall(t *testing.T, tokenName, method string, params ...string) string {
	t.Helper()
	if params == nil {
		params = []string{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/", p.rpc), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token(tokenName))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func (p *proc) console(line string) string {
	var out bytes.Buffer
	_ = control.Call(control.SocketPath(p.dir), line, &out)
	return out.String()
}

func TestNetworkOfProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts four daemons and runs several minutes of chain time")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "nosod")
	// the daemons are built without -race: four of them under the race
	// detector would not keep up with the fast clock
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	base := freePorts(t, 4)
	netDir := filepath.Join(root, "net")
	init := exec.Command(bin, "init-network", "-dir", netDir, "-nodes", "4", "-proposers", "3",
		"-base-port", strconv.Itoa(base), "-rpc-base-port", strconv.Itoa(base+10), "-clock-scale", strconv.Itoa(netScale))
	init.Env = append(os.Environ(), "NOSO_WALLET_PASSPHRASE=correct horse battery")
	out, err := init.CombinedOutput()
	if err != nil {
		t.Fatalf("init-network: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "PRIVATE") {
		t.Fatal("init-network printed private material")
	}
	var ps []*proc
	for i := 0; i < 4; i++ {
		ps = append(ps, &proc{dir: filepath.Join(netDir, fmt.Sprintf("node%d", i+1)), port: base + i, rpc: base + 10 + i})
	}
	defer func() {
		for _, p := range ps {
			p.stop()
		}
	}()
	dump := func() string {
		var s []string
		for i, p := range ps {
			n, h := p.tip()
			s = append(s, fmt.Sprintf("node%d h=%d tip=%s", i+1, n, h))
		}
		return strings.Join(s, " | ")
	}
	converged := func(min int, which ...int) bool {
		var tip string
		var height int
		for k, i := range which {
			n, h := ps[i].tip()
			if n < min {
				return false
			}
			if k == 0 {
				tip, height = h, n
			} else if h != tip || n != height {
				return false
			}
		}
		return true
	}
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
				if len(raw) > 3000 {
					raw = raw[len(raw)-3000:]
				}
				t.Logf("--- node%d log tail:\n%s", i+1, raw)
			}
		}
		t.Fatalf("timeout waiting for %s: %s", what, dump())
	}
	for _, p := range ps {
		p.start(t, bin)
	}
	all := []int{0, 1, 2, 3}

	// 1. blocks from three proposers reach everybody
	wait("first blocks on all four nodes", 120*time.Second, func() bool { return converged(5, all...) })

	// 2. an order over RPC reaches every node's chain
	var from *proc
	wait("a funded proposer", 120*time.Second, func() bool {
		for _, p := range ps[:3] {
			r := p.rpcCall(t, "RPCToken", "getwalletbalance")
			if m := regexp.MustCompile(`"balance":"?(\d+)`).FindStringSubmatch(r); m != nil && m[1] != "0" {
				from = p
				return true
			}
		}
		return false
	})
	dest := "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"
	var res string
	for try := 0; try < 60; try++ { // ERROR 20: the node is a moment behind a new block
		res = from.rpcCall(t, "RPCSpendToken", "sendfunds", dest, "100000", "test")
		if !strings.Contains(res, `"result":20`) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !strings.Contains(res, "OR") || strings.Contains(res, "ERROR") {
		t.Fatalf("sendfunds: %s", res)
	}
	wait("the payment on all nodes", 120*time.Second, func() bool {
		for _, p := range ps {
			if !strings.Contains(p.rpcCall(t, "RPCToken", "getaddressbalance", dest), "100000") {
				return false
			}
		}
		return true
	})

	// 3. a node restarts and catches up
	h, _ := ps[1].tip()
	ps[1].stop()
	ps[1].start(t, bin)
	wait("the restarted node to catch up", 150*time.Second, func() bool { return converged(h+3, all...) })

	// 4. cut {1,2} | {3,4}; both halves go on building, so they differ
	cut := func(cmd string, a, b []int) {
		for _, i := range a {
			for _, j := range b {
				ps[i].console(fmt.Sprintf("%s 127.0.0.1:%d", cmd, ps[j].port))
				ps[j].console(fmt.Sprintf("%s 127.0.0.1:%d", cmd, ps[i].port))
			}
		}
	}
	cut("denypeer", []int{0, 1}, []int{2, 3})
	wait("the halves to diverge", 150*time.Second, func() bool {
		n0, h0 := ps[0].tip()
		n2, h2 := ps[2].tip()
		return n0 > h && n2 > h && h0 != h2
	})
	time.Sleep(15 * time.Second)
	for _, p := range ps {
		p.console("allowpeer all")
	}

	// 5. one chain of at least 50 blocks everywhere
	wait("one chain of 50 blocks", 300*time.Second, func() bool { return converged(50, all...) })
	t.Logf("final: %s", dump())
}
