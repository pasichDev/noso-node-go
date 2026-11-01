package network

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// connected returns two engines with B dialled to A; slot 1 on both sides.
func connected(t *testing.T) (a, b *Engine, na, nb *node.Node, clkA *clock) {
	var ca, cb clock
	base := int64(consensus.GenesysTimeStamp) + 600*10 + 100
	ca.v.Store(base)
	cb.v.Store(base)
	na, nb = mkNode(t, &ca), mkNode(t, &cb)
	a, b = NewEngine(na), NewEngine(nb)
	a.MinPeers, b.MinPeers = 1, 1
	if err := a.StartServer(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Stop(); b.Stop() })
	_, port, _ := splitHostPort(a.ServerAddr())
	seeds := "NORMAL 127.0.0.1;" + port + ": ts2.aco.net: null: null: NpryectdevepmentfundsGE:"
	na.CFG.Save(seeds)
	nb.CFG.Save(seeds)
	na.SetConStatus(3)
	if b.ConnectClient("127.0.0.1", port) == 0 {
		t.Fatal("connect")
	}
	drive(t, "handshake", 5*time.Second, []*Engine{a, b}, func() bool { return a.Peer(1).Autentic && b.Peer(1).Autentic })
	return a, b, na, nb, &ca
}

// settle ticks the engines for a while so queued lines are delivered and
// processed.
func settle(es ...*Engine) {
	for i := 0; i < 30; i++ {
		for _, e := range es {
			e.Tick()
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitClosed(t *testing.T, e *Engine, es ...*Engine) {
	t.Helper()
	drive(t, "slot closed", 5*time.Second, append([]*Engine{e}, es...), func() bool { return e.Peer(1).Tipo == "" })
}

// C-01: SETCFGDATA that nobody asked for is ignored; an answer must carry a
// signature by the configured key.
func TestC01_UnsolicitedAndUnsignedConfig(t *testing.T) {
	a, b, _, nb, _ := connected(t)
	kp := crypto.GenerateKeyPair()
	nb.UpdateOptions(func(o *node.StorageOptions) { o.ConfigKey = kp.PublicKey })
	content := "STOP 6.6.6.6;8080: ts2.aco.net: null: null: NpryectdevepmentfundsGE:"
	sig := crypto.SignCanonical(kp.PrivateKey, "CFG1", node.CFGFields(1, content)...)
	line := a.ProtocolLine(31) + "1 " + sig + " " + content
	before := nb.CFG.DataStr()
	a.TextToSlot(1, line) // unsolicited
	settle(a, b)
	if nb.CFG.DataStr() != before {
		t.Fatal("C-01: unsolicited signed configuration installed")
	}
	// requested, but unsigned (the old MD5-prefix style)
	b.expectReply(1, "CFG")
	a.TextToSlot(1, a.ProtocolLine(31)+"2 AAAA "+content)
	settle(a, b)
	if nb.CFG.DataStr() != before {
		t.Fatal("C-01: unsigned configuration installed")
	}
	// requested and signed by the configured key
	b.expectReply(1, "CFG")
	a.TextToSlot(1, line)
	drive(t, "accepted", 3*time.Second, []*Engine{a, b}, func() bool { return nb.CFG.DataStr() == content })
}

// C-02, H-05, H-06: pushed files end the connection and change nothing.
func TestC02_H05_H06_UnsolicitedFilesRefused(t *testing.T) {
	for _, tc := range []struct{ label, id string }{{"BLOCKZIP", "C-02"}, {"RESUMENFILE", "H-05"}, {"SUMARYFILE", "C-03"},
		{"GVTSFILE", "M-14"}, {"PSOSFILE", "H-06"}} {
		a, b, _, nb, _ := connected(t)
		hdrBefore := nb.Headers.Hash()
		sumBefore := nb.Summary.Hash()
		if err := a.peers.slots[1].conn.WriteStream(tc.label, []byte("poison")); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, b, a)
		if nb.Headers.Hash() != hdrBefore || nb.Summary.Hash() != sumBefore || nb.MyLastBlock() != 0 {
			t.Fatalf("%s %s: unsolicited %s changed state", tc.id, tc.label, tc.label)
		}
		a.Stop()
		b.Stop()
	}
}

// Requested files must match the hash the peer advertised.
func TestH05_RequestedFileHashChecked(t *testing.T) {
	a, b, _, nb, _ := connected(t)
	hdr := nb.Headers.Hash()
	b.expectReply(1, "RESUMEN")
	bad := make([]byte, 70*3) // whole records but not the advertised file
	_ = a.peers.slots[1].conn.WriteStream("RESUMENFILE", bad)
	waitClosed(t, b, a)
	if nb.Headers.Hash() != hdr {
		t.Fatal("H-05: headers replaced by a file that does not match the advertised hash")
	}
}

// H-04: quorum over all configured seeds, duplicates removed.
func TestH04_QuorumAndDedupe(t *testing.T) {
	a, b, _, _, _ := connected(t)
	_, port, _ := splitHostPort(a.ServerAddr())
	b.SetNodesArray("127.0.0.1;" + port + ":127.0.0.1;" + port + ":127.0.0.1;" + port + ":")
	if len(b.nodesArr) != 1 {
		t.Fatalf("seed list not deduplicated: %d", len(b.nodesArr))
	}
	if c := b.CalculateConsensus(); c[0] == "" {
		t.Fatal("single reachable seed of one must be a quorum")
	}
	// one of three seeds answers: no quorum
	b.SetNodesArray("127.0.0.1;" + port + ":127.0.0.2;1:127.0.0.3;2:")
	if c := b.CalculateConsensus(); c[0] != "" {
		t.Fatal("H-04: a minority of the configured seeds produced a consensus")
	}
}

func TestH04_SignedStatus(t *testing.T) {
	a, b, na, nb, _ := connected(t)
	w := na.Wallet.At(0)
	na.UpdateOptions(func(o *node.StorageOptions) { o.MNSign = w.Hash })
	nb.UpdateOptions(func(o *node.StorageOptions) { o.SeedKeys = "127.0.0.1=" + w.PublicKey })
	good := a.SignedStatus()
	if _, ok := b.checkSignedStatus("127.0.0.1", good); !ok {
		t.Fatal("signed status refused")
	}
	unsigned := good[:strings.LastIndex(good, " SIG:")]
	if _, ok := b.checkSignedStatus("127.0.0.1", unsigned); ok {
		t.Fatal("H-04: unsigned status accepted for a seed with a configured key")
	}
	tampered := strings.Replace(good, "NODESTATUS 1", "NODESTATUS 9", 1)
	if _, ok := b.checkSignedStatus("127.0.0.1", tampered); ok {
		t.Fatal("H-04: tampered status accepted")
	}
}

// M-04: a peer cannot choose our public IP.
func TestM04_PeerCannotSetMyIP(t *testing.T) {
	a, _, _, _, clk := connected(t)
	c, err := net.Dial("tcp", a.ServerAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("PSK 8.8.8.8 0.4.4Ab9 " + strconv.FormatInt(clk.now(), 10) + "\r\n"))
	time.Sleep(300 * time.Millisecond)
	if a.MyPublicIP() != "" {
		t.Fatalf("M-04: public IP set to %q by a peer", a.MyPublicIP())
	}
}

// M-05: MNVER needs a nonce and the answer is bound to it and to the key.
func TestM05_MNVERChallenge(t *testing.T) {
	a, _, na, _, _ := connected(t)
	w := na.Wallet.At(0)
	fund := na.Wallet.At(0).Hash
	na.UpdateOptions(func(o *node.StorageOptions) { o.MNSign = w.Hash; o.MNFunds = fund })
	_, port, _ := splitHostPort(a.ServerAddr())
	ask := func(l string) string { return a.RequestLine("127.0.0.1", mustAtoi(port), l) }
	if ask("MNVER") != "False" || ask("MNVER short") != "False" {
		t.Fatal("answered without a proper nonce")
	}
	// synchronise A's view with the consensus so it will answer
	a.consMu.Lock()
	a.cons = make([]string, 21)
	a.cons[2] = codec3(na.MyLastBlock())
	a.cons[10] = na.MyLastBlockHash()
	a.cons[17] = na.Summary.Hash()[:5]
	a.cons[5] = na.Headers.Hash()[:5]
	a.consMu.Unlock()
	nonce := "0123456789abcdef"
	line := ask("MNVER " + nonce)
	m := node.MNode{Fund: fund, Sign: w.Hash}
	if !node.CheckVerificationLine(line, nonce, na.SyncTus(), m) {
		t.Fatalf("valid answer rejected: %q", line)
	}
	if node.CheckVerificationLine(line, "another-nonce-1234", na.SyncTus(), m) {
		t.Fatal("M-05: answer replayed under a different nonce")
	}
	if node.CheckVerificationLine("True x y z", nonce, na.SyncTus(), m) {
		t.Fatal("M-05: unsigned 'True' accepted")
	}
}

func codec3(v int64) string { return strconv.FormatInt(v, 10) }

// M-03: median of several answers, bounded correction.
func TestM03_MedianOffset(t *testing.T) {
	if _, ok := MedianOffset([]int64{5}); ok {
		t.Fatal("single reply trusted")
	}
	if m, ok := MedianOffset([]int64{1, 2, 900}); !ok || m != 2 {
		t.Fatalf("outlier not ignored: %d %v", m, ok)
	}
	if _, ok := MedianOffset([]int64{4000, 4001, 4002}); ok {
		t.Fatal("huge correction accepted")
	}
}

// M-07, M-08, L-04: per-peer budgets.
func TestRateLimits(t *testing.T) {
	var clk clock
	clk.v.Store(1_700_000_000)
	e := NewEngine(mkNode(t, &clk))
	if !e.filePermit("$GETSUMARY", "1.1.1.1") || e.filePermit("$GETSUMARY", "1.1.1.1") {
		t.Fatal("same peer must wait 10 s")
	}
	if !e.filePermit("$GETSUMARY", "2.2.2.2") { // L-04: another peer is not starved
		t.Fatal("L-04: one peer's request blocked another peer")
	}
	clk.v.Add(11)
	if !e.filePermit("$GETSUMARY", "1.1.1.1") {
		t.Fatal("limit does not expire")
	}
	for i := 0; i < 10; i++ {
		if !e.heavyOK("3.3.3.3") {
			t.Fatal("early heavy refusal")
		}
	}
	if e.heavyOK("3.3.3.3") || !e.heavyOK("4.4.4.4") {
		t.Fatal("M-08: heavy request budget")
	}
	for i := 0; i < 200; i++ {
		if !e.lineBudget(7, "PSK 2 v 1 $PING x") {
			t.Fatal("early line refusal")
		}
	}
	if e.lineBudget(7, "PSK 2 v 1 $PING x") || !e.lineBudget(8, "PSK 2 v 1 $PING x") {
		t.Fatal("M-07: line budget")
	}
}

// M-06/M-15: a panic in a handler is contained.
func TestM15_PanicContained(t *testing.T) {
	var clk clock
	clk.v.Store(1_700_000_000)
	e := NewEngine(mkNode(t, &clk))
	a, b := net.Pipe()
	defer b.Close()
	func() {
		defer e.recoverPanic("test", NewConn(a))
		var m map[string]int
		m["x"] = 1 // nil map write
	}()
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("connection of the panicking handler left open")
	}
}

// H-02 on the wire: a directive can be accepted once.
func TestH02_DirectiveOverTheWire(t *testing.T) {
	_, b, _, nb, _ := connected(t)
	kp := crypto.GenerateKeyPair()
	nb.UpdateOptions(func(o *node.StorageOptions) { o.AdminKey = kp.PublicKey })
	exp := nb.MyLastBlock() + 5
	sig := crypto.SignCanonical(kp.PrivateKey, "DIRECTIVE1", node.DirectiveFields(1, exp, "SETMODE EMPTY")...)
	line := "PSK 2 0.4.4Ab9 1 ADMINMSG 1 " + strconv.FormatInt(exp, 10) + " SETMODE_EMPTY " + sig
	b.addIncoming(1, line)
	b.Tick()
	if nb.CFG.Param(0) != "EMPTY" {
		t.Fatal("valid directive not applied")
	}
	nb.CFG.SetData("NORMAL", 0)
	b.addIncoming(1, line) // replay
	b.Tick()
	if nb.CFG.Param(0) != "NORMAL" {
		t.Fatal("H-02: replayed directive applied")
	}
	// update/restart directives do not exist
	sig2 := crypto.SignCanonical(kp.PrivateKey, "DIRECTIVE1", node.DirectiveFields(2, exp, "UPDATE 9.9.9")...)
	b.addIncoming(1, "PSK 2 0.4.4Ab9 1 ADMINMSG 2 "+strconv.FormatInt(exp, 10)+" UPDATE_9.9.9 "+sig2)
	b.Tick()
}

// M-10: by default a node does not propose blocks; it follows.
func TestM10_OnlyProposersBuild(t *testing.T) {
	var clk clock
	clk.v.Store(int64(consensus.GenesysTimeStamp) + 600*5 + 100)
	n := mkNode(t, &clk)
	n.Log = func(ch, m string) { t.Log(ch, m) }
	e := NewEngine(n)
	e.Log = n.Log
	n.SetConStatus(3)
	e.mu.Lock()
	e.buildNMSBlock = clk.now() - 1
	e.mu.Unlock()
	e.cons = []string{"x", "", "0"}
	e.Tick()
	if n.MyLastBlock() != 0 {
		t.Fatal("M-10: a node that is not a configured proposer built a block")
	}
	n.UpdateOptions(func(o *node.StorageOptions) { o.BuildBlocks = true })
	if err := n.SetProposers([]string{n.Wallet.At(0).PublicKey}); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	e.buildNMSBlock = (clk.now() / 600) * 600
	e.mu.Unlock()
	clk.v.Store((clk.now()/600)*600 + 2)
	n.SetConStatus(3)
	e.Tick()
	if n.MyLastBlock() != 1 {
		t.Fatalf("configured proposer did not build (last %d)", n.MyLastBlock())
	}
}
