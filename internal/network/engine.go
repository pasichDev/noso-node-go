package network

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// DefaultMinPeers is the number of connections that makes a node count as
// connected. One is enough to hear where the chain stands and to be heard;
// the blocks are verified whoever delivers them, and a node that would sit
// idle while one of its three siblings restarts is worse than the original's
// stricter 3 (mpred.pas:499).
const DefaultMinPeers = 1

// Engine runs the peer-to-peer side of a node: the listener, the peer
// slots, protocol processing, consensus polling and synchronisation. It
// mirrors the threads of masterpaskalform.pas (heartbeat, KeepConnect,
// SendOutMsjs, MNs) as goroutines.
type Engine struct {
	N *node.Node

	peers peerTable

	mu          sync.Mutex
	slotCount   int
	listener    net.Listener
	serverOn    bool
	keepServer  bool
	serverPort  int
	serverStart int64

	// consensus
	cons              []string
	consMu            sync.Mutex
	nodesArr          []nodeConsensus
	consStats         ConsensusStats
	lastConsensusTime int64

	// bots / ip control (nosoipcontrol.pas, nosonetwork.pas bots)
	botsMu       sync.Mutex
	bots         map[string]int64
	ipCtl        map[string]int
	lastIPsClear int64
	lastBotClear int64

	myPublicIP string

	mnMu         sync.Mutex
	mnFundsBlock int64
	mnFunds      map[string]bool // funds that already have a report queued this block

	// rate limits (function level `const` variables of the Pascal code)

	// request throttles (nosonetwork.pas:155-167)
	lastTimeRequestSumary, lastTimeRequestBlock, lastTimeRequestResumen int64
	lastTimePendingRequested, lastTimeMNHashRequested                   int64
	lastTimeMNsRequested, lastTimeChecksRequested                       int64
	lastTimeGVTsRequest, lastTimePSOsRequest, lastRunMNVerification     int64
	lastSyncWithMainnet, lastTimeReportMyMN, lastPing                   int64
	forceCompleteHeadersDownload                                        bool
	downloadHeaders, downloadSumary, downloadBlocks                     bool
	downloadGVTs, downloadPSOs                                          bool
	statusConnected                                                     bool
	rebuildingSumary                                                    bool
	buildNMSBlock                                                       int64
	canBuild                                                            bool
	mnsRandomWait                                                       int64
	engineLastUpdate                                                    int64

	// MinPeers is the connection count that moves the node from state 1 to
	// 2. It is 3 on the real network (mpred.pas:499); tests lower it.
	MinPeers int

	// BindAddr is the local address the peer listener binds to. Empty means
	// every interface (a public node); a test network or a node that must stay
	// on one machine sets it to 127.0.0.1 (nosod -bind).
	BindAddr string

	// TraceOrder, when set, receives every order line SendFunds hands to a
	// node (tests only: the raw signed order is not printed to the user).
	TraceOrder func(line string)

	// Dial opens outgoing connections; replaceable for tests.
	Dial func(addr string, timeout time.Duration) (net.Conn, error)

	// Wall is the clock of the connection timers (ping timeouts, request
	// throttles, reply windows, budgets). It is nil for the node's chain clock;
	// a test network whose chain clock runs faster than real time sets it to
	// real seconds, so that a 15 second ping timeout stays 15 real seconds.
	Wall func() int64

	// network access control (see DenyPeer) and the block puller
	denyMu   sync.Mutex
	denied   map[string]bool
	syncMu   sync.Mutex
	peerSync map[*slot]*pullState
	pullSlot *slot
	connMu   sync.Mutex
	conns    map[*Conn]struct{} // accepted connections that are not peers yet
	rejected map[string]bool    // peer tip|own tip pairs that were weighed and lost
	pullAt   int64
	pullSeq  uint64

	Log func(ch, msg string)

	big sync.Mutex // guards the throttle and download flags shared by Tick and the slot goroutines (M-06)

	expMu  sync.Mutex
	expect map[expectKey]int64

	limMu     sync.Mutex
	fileLast  map[string]int64   // kind+ip -> last served
	heavy     map[string][]int64 // ip -> recent heavy requests
	lineLog   map[int][]int64    // slot -> recent line times
	bulkLog   map[int][]int64    // slot -> recent bulk line times
	byteWin   map[int]*window    // slot -> bytes received in the current window
	mnRepoWin map[int]*window    // slot -> $MNREPO lines in the current window
	sendSlots chan struct{}      // bounds file transfers being sent at once

	stop chan struct{}
	wg   sync.WaitGroup
}

// NewEngine builds an engine around a node and wires the node hooks.
func NewEngine(n *node.Node) *Engine {
	e := &Engine{N: n, MinPeers: DefaultMinPeers, mnFunds: map[string]bool{}, mnFundsBlock: -1, bots: map[string]int64{}, ipCtl: map[string]int{},
		stop: make(chan struct{}), denied: map[string]bool{}, peerSync: map[*slot]*pullState{}, rejected: map[string]bool{}, conns: map[*Conn]struct{}{},
		expect: map[expectKey]int64{}, fileLast: map[string]int64{}, heavy: map[string][]int64{}, lineLog: map[int][]int64{}, bulkLog: map[int][]int64{},
		byteWin: map[int]*window{}, mnRepoWin: map[int]*window{}, sendSlots: make(chan struct{}, maxSendsAtOnce)}
	e.Dial = func(addr string, to time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", addr, to) }
	n.Consensus = e.GetConsensus
	n.ServerOn = func() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.serverOn }
	n.ServerPort = func() int { e.mu.Lock(); defer e.mu.Unlock(); return e.serverPort }
	n.TotalConns = e.TotalConnections
	n.Broadcast = e.OutgoingAdd
	n.OnNewBlock = func() { e.OutgoingAdd(e.ProtocolLine(3)) }
	if n.Log != nil {
		e.Log = n.Log
	}
	return e
}

// now is the connection clock in seconds (see Wall).
func (e *Engine) now() int64 {
	if e.Wall != nil {
		return e.Wall()
	}
	return e.N.UTCTime()
}

func (e *Engine) nowStr() string { return codec.IntToStr(e.now()) }

func (e *Engine) logf(ch, msg string) {
	if e.Log != nil {
		e.Log(ch, msg)
	} else if e.N.Log != nil {
		e.N.Log(ch, msg)
	}
}

// ProtocolLine mirrors ProtocolLine (nosonetwork.pas:407-436). COMPAT: this
// header advertises the version as "0.4.4zzz" (not the release suffix that
// GetPTCEcn uses).
func (e *Engine) ProtocolLine(code int) string {
	header := "PSK " + strconv.Itoa(node.Protocol) + " " + node.MainnetVersion + "zzz " + e.N.UTCTimeStr() + " "
	var s string
	switch code {
	case 3:
		s = "$PING " + e.PingString()
	case 4:
		s = "$PONG " + e.PingString()
	case 5:
		s = "$GETPENDING"
	case 6:
		s = "$GETSUMARY"
	case 7:
		s = "$GETRESUMEN"
	case 8:
		s = "$LASTBLOCK " + codec.IntToStr(e.N.MyLastBlock())
	case 9:
		s = "$CUSTOM "
	case 11:
		s = "$GETMNS"
	case 12:
		s = "$BESTHASH"
	case 13:
		s = "$MNREPO " + e.N.MNReportString(e.N.MyLastBlock())
	case 14:
		s = "$MNCHECK "
	case 15:
		s = "$GETCHECKS"
	case 16:
		s = "GETMNSFILE"
	case 17:
		s = "MNFILE"
	case 18:
		s = "GETHEADUPDATE " + codec.IntToStr(e.N.MyLastBlock())
	case 19:
		s = "HEADUPDATE"
	case 20:
		s = "$GETGVTS"
	case 21:
		s = "$SNDGVT "
	case 30:
		s = "GETCFGDATA"
	case 31:
		s = "SETCFGDATA $"
	case 32:
		s = "$GETPSOS"
	}
	return header + s
}

// PingString mirrors GetPingString (nosonetwork.pas:385-405).
func (e *Engine) PingString() string {
	port := -1
	e.mu.Lock()
	if e.serverOn {
		port = e.serverPort
	}
	e.mu.Unlock()
	n := e.N
	return codec.IntToStr(int64(e.TotalConnections())) + " " +
		codec.IntToStr(n.MyLastBlock()) + " " +
		n.MyLastBlockHash() + " " +
		n.Summary.Hash() + " " +
		codec.IntToStr(int64(n.PendingCount())) + " " +
		n.Headers.Hash() + " " +
		codec.IntToStr(int64(n.ConStatus())) + " " +
		codec.IntToStr(int64(port)) + " " +
		codec.Copy(n.MNFile.Hash(), 0, 5) + " " +
		codec.IntToStr(int64(n.MNsListLen())) + " " +
		"null " +
		codec.IntToStr(int64(n.ChecksCount())) + " " +
		n.GVTs.Hash() + " " +
		codec.Copy(crypto.IDHash(n.CFG.DataStr()), 0, 5) + " " +
		codec.Copy(n.PSOs.FileHash(), 0, 5)
}

// NodeStatusString mirrors GetNodeStatusString (mpred.pas:965-979).
func (e *Engine) NodeStatusString() string {
	n := e.N
	last := n.LastBlockData()
	return codec.IntToStr(int64(e.TotalConnections())) + " " + codec.IntToStr(n.MyLastBlock()) + " " +
		codec.IntToStr(int64(n.PendingCount())) + " " + codec.IntToStr(n.UTCTime()-e.engineLastUpdateValue()) + " " +
		codec.Copy(n.Headers.Hash(), 0, 5) + " " + node.MainnetVersion + node.NodeRelease + " " + n.UTCTimeStr() + " " +
		codec.Copy(n.MNFile.Hash(), 0, 5) + " " + codec.IntToStr(int64(n.MNsListLen())) + " " +
		n.MyLastBlockHash() + " null " + codec.IntToStr(last.TimeEnd) + " " + last.AccountMiner + " " +
		codec.IntToStr(int64(n.ChecksCount())) + " " + orNull(codec.Parameter(last.Solution, 2)) + " " +
		orNull(codec.Parameter(last.Solution, 1)) + " " + codec.Copy(n.Summary.Hash(), 0, 5) + " " +
		codec.Copy(n.GVTs.Hash(), 0, 5) + " " + codec.Copy(n.CFG.Hash(), 0, 5) + " " +
		codec.Copy(n.PSOs.FileHash(), 0, 5) + " " +
		// full hashes, items 21..26 of the consensus (C-03, H-06)
		n.Headers.Hash() + " " + n.MNFile.Hash() + " " + n.Summary.Hash() + " " + n.GVTs.Hash() + " " +
		n.CFG.Hash() + " " + n.PSOs.FileHash()
}

func (e *Engine) engineLastUpdateValue() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.engineLastUpdate == 0 {
		return e.N.UTCTime()
	}
	return e.engineLastUpdate
}

// Bots (nosonetwork.pas:1372-1419) -----------------------------------------

// UpdateBotData registers a refusal timestamp for ip (seeds are exempt).
func (e *Engine) UpdateBotData(ip string) {
	if e.N.IsSeedNode(ip) || isLoopback(ip) { // every local node shares the address: banning it would ban them all
		return
	}
	e.botsMu.Lock()
	e.bots[ip] = e.now()
	e.botsMu.Unlock()
}

// BotExists mirrors BotExists.
func (e *Engine) BotExists(ip string) bool {
	e.botsMu.Lock()
	defer e.botsMu.Unlock()
	_, ok := e.bots[ip]
	return ok
}

// Bots returns the banned IPs.
func (e *Engine) Bots() []string {
	e.botsMu.Lock()
	defer e.botsMu.Unlock()
	var out []string
	for ip := range e.bots {
		out = append(out, ip)
	}
	return out
}

// DeleteBots mirrors DeleteBots.
func (e *Engine) DeleteBots() {
	e.botsMu.Lock()
	e.bots = map[string]int64{}
	e.lastBotClear = e.N.UTCTime()
	e.botsMu.Unlock()
}

// AddIPControl mirrors nosoipcontrol.pas:AddIPControl.
func (e *Engine) AddIPControl(ip string) int {
	if isLoopback(ip) {
		return 0
	}
	e.botsMu.Lock()
	defer e.botsMu.Unlock()
	e.ipCtl[ip]++
	return e.ipCtl[ip]
}

// ClearIPControls mirrors ClearIPControls.
func (e *Engine) ClearIPControls() {
	e.botsMu.Lock()
	e.ipCtl = map[string]int{}
	e.lastIPsClear = e.N.UTCTime()
	e.botsMu.Unlock()
}

// MyPublicIP returns the address peers reported for us.
func (e *Engine) MyPublicIP() string { return e.myPublicIP }

// IsSafeIP mirrors mpred.pas:981-985 (substring test on the seeds field).
func (e *Engine) IsSafeIP(ip string) bool {
	return len(ip) > 0 && contains(e.N.CFG.Param(1), ip)
}

func contains(s, sub string) bool { return len(sub) > 0 && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = consensus.SecondsPerBlock

// expectKey names an outstanding request. FIX: it is bound to the slot
// object of the connection the request went out on, not to the slot number,
// so a connection that replaces a closed one in the same slot inherits
// nothing.
type expectKey struct {
	s    *slot
	kind string
}

// replyWindow is how long an answer to a request is accepted.
const replyWindow = 60

// expectReply records that we asked slot for `kind`. FIX(C-01, C-02, H-05,
// H-06): transfers and configuration are accepted only as answers.
func (e *Engine) expectReply(slot int, kind string) {
	s := e.slotObj(slot)
	if s == nil {
		return
	}
	e.expMu.Lock()
	e.expect[expectKey{s, kind}] = e.now() + replyWindow
	e.expMu.Unlock()
}

// forgetSlot drops everything remembered about a closed connection.
func (e *Engine) forgetSlot(s *slot, i int) {
	e.expMu.Lock()
	for k := range e.expect {
		if k.s == s {
			delete(e.expect, k)
		}
	}
	e.expMu.Unlock()
	e.limMu.Lock()
	delete(e.lineLog, i)
	delete(e.bulkLog, i)
	delete(e.byteWin, i)
	delete(e.mnRepoWin, i)
	e.limMu.Unlock()
}

// takeReply consumes an outstanding expectation.
func (e *Engine) takeReply(slot int, kind string) bool {
	s := e.slotObj(slot)
	if s == nil {
		return false
	}
	e.expMu.Lock()
	defer e.expMu.Unlock()
	k := expectKey{s, kind}
	exp, ok := e.expect[k]
	delete(e.expect, k)
	return ok && exp >= e.now()
}

// request sends a protocol request to a slot and expects the answer.
func (e *Engine) request(slot int, code int, kind string) {
	e.expectReply(slot, kind)
	e.PTCSendLine(slot, e.ProtocolLine(code))
}

// filePermit limits how often one peer may fetch a file kind (10 s each).
// FIX(L-04): the original kept one global timer per file kind, so one peer's
// request starved every other peer (mpprotocol.pas:472-480, 509-517).
func (e *Engine) filePermit(kind, ip string) bool {
	now := e.now()
	e.limMu.Lock()
	defer e.limMu.Unlock()
	k := kind + "|" + ip
	gap := int64(10)
	if kind == "$LASTBLOCK" {
		gap = 1 // catching up is many requests; every answer is verified block by block
	}
	if now < e.fileLast[k]+gap {
		return false
	}
	e.fileLast[k] = now
	if len(e.fileLast) > 4096 {
		e.fileLast = map[string]int64{}
	}
	return true
}

// heavyOK allows a peer ten costly one-shot requests per minute (M-08).
func (e *Engine) heavyOK(ip string) bool {
	if isLoopback(ip) {
		return true // every local node shares the address; see isLoopback
	}
	now := e.now()
	e.limMu.Lock()
	defer e.limMu.Unlock()
	l := e.heavy[ip][:0]
	for _, t := range e.heavy[ip] {
		if t > now-60 {
			l = append(l, t)
		}
	}
	if len(l) >= 10 {
		e.heavy[ip] = l
		return false
	}
	e.heavy[ip] = append(l, now)
	if len(e.heavy) > 4096 {
		e.heavy = map[string][]int64{}
	}
	return true
}

// lineBudget allows 200 protocol lines per 10 seconds per connection (M-07).
// FIX(H5): the answers to $GETMNS and $GETPENDING are one line per masternode
// or order, so those line kinds (reports, orders, customisations) are counted
// against a bulk budget instead; each is capped by its own limits (the byte
// budget, the $MNREPO budget, the pool).
func (e *Engine) lineBudget(slot int, line string) bool {
	now := e.now()
	log, limit := e.lineLog, 200
	switch codec.ASCIIUpper(codec.Parameter(line, 4)) {
	case "$MNREPO", "ORDER", "$CUSTOM", "$SNDGVT":
		log, limit = e.bulkLog, bulkLines
	}
	e.limMu.Lock()
	defer e.limMu.Unlock()
	l := log[slot][:0]
	for _, t := range log[slot] {
		if t > now-10 {
			l = append(l, t)
		}
	}
	if len(l) >= limit {
		log[slot] = l
		return false
	}
	log[slot] = append(l, now)
	return true
}

// Per-peer budgets against memory exhaustion (M-07). A line is capped by
// command, and each slot has a byte budget and a $MNREPO budget.
const (
	maxLineDefault   = 64 << 10        // ORDER, $MNCHECK, GETHEADUPDATE ... are small
	maxLineMNRepo    = 2 << 10         // a masternode report
	maxLineMNFile    = maxMNText + 512 // the only large line
	byteBudget       = 16 << 20        // bytes of protocol lines per slot and window
	byteWindow       = 10              // seconds
	mnRepoBudget     = 3000            // $MNREPO lines per slot and window
	mnRepoWindow     = 600             // seconds
	maxIncomingBytes = 8 << 20         // queued, unprocessed lines per slot
	maxSendsAtOnce   = 8
	bulkLines        = 6000 // $MNREPO / ORDER lines per slot and 10 seconds (answers to $GETMNS and $GETPENDING)
)

type window struct {
	start int64
	n     int
}

// charge adds amount to the slot's counter and reports whether it is still
// within limit for the current window of span seconds.
func (e *Engine) charge(m map[int]*window, slot, amount, span, limit int) bool {
	now := e.now()
	e.limMu.Lock()
	defer e.limMu.Unlock()
	w := m[slot]
	if w == nil || now >= w.start+int64(span) {
		w = &window{start: now}
		m[slot] = w
	}
	w.n += amount
	return w.n <= limit
}

// lineAllowed applies the size and budget rules to one received line.
func (e *Engine) lineAllowed(sl int, line string) bool {
	max := maxLineDefault
	switch codec.ASCIIUpper(codec.Parameter(line, 4)) {
	case "MNFILE":
		max = maxLineMNFile
	case "$MNREPO":
		max = maxLineMNRepo
		if !e.charge(e.mnRepoWin, sl, 1, mnRepoWindow, mnRepoBudget) {
			return false
		}
	}
	if len(line) > max {
		return false
	}
	return e.charge(e.byteWin, sl, len(line), byteWindow, byteBudget)
}

// orNull keeps a status field from vanishing when it is empty (the genesis
// block has no solution): fields are separated by blanks, so an empty one
// would shift every later field, including the full hashes.
func orNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

// isLoopback reports whether ip is a local address. Nodes started on one
// machine share it, so per-address rules (one connection, bans, flood
// counters) cannot tell them apart and do not apply.
func isLoopback(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && a.IsLoopback()
}

// peerKey names the peer behind a slot for per-peer budgets: its address, or
// the slot itself for loopback peers.
func (e *Engine) peerKey(sl int) string {
	p := e.peers.get(sl)
	if isLoopback(p.IP) {
		return p.IP + "#" + strconv.Itoa(sl)
	}
	return p.IP
}

// DenyPeer cuts the node off from host:port: an open connection to it is
// closed, it is not dialled and a connection from it is refused. It is an
// operator control (console command `denypeer`) and the way a test creates a
// network partition.
func (e *Engine) DenyPeer(hostport string) {
	e.denyMu.Lock()
	e.denied[hostport] = true
	e.denyMu.Unlock()
	for i := 1; i <= MaxConnections; i++ {
		p := e.peers.get(i)
		if p.Tipo != "" && e.isDenied(p.IP, p.ListeningPort) {
			e.CloseSlot(i)
		}
	}
}

// AllowPeer undoes DenyPeer; "all" clears the list.
func (e *Engine) AllowPeer(hostport string) {
	e.denyMu.Lock()
	if hostport == "all" {
		e.denied = map[string]bool{}
	} else {
		delete(e.denied, hostport)
	}
	e.denyMu.Unlock()
}

// DeniedPeers lists the denied host:port entries.
func (e *Engine) DeniedPeers() []string {
	e.denyMu.Lock()
	defer e.denyMu.Unlock()
	var out []string
	for k := range e.denied {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) isDenied(ip string, port int) bool {
	e.denyMu.Lock()
	defer e.denyMu.Unlock()
	return len(e.denied) > 0 && port > 0 && e.denied[net.JoinHostPort(ip, strconv.Itoa(port))]
}
