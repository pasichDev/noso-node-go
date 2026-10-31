package network

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
)

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
	ConsStats         ConsensusStats
	lastConsensusTime int64

	// bots / ip control (nosoipcontrol.pas, nosonetwork.pas bots)
	botsMu       sync.Mutex
	bots         map[string]int64
	ipCtl        map[string]int
	lastIPsClear int64
	lastBotClear int64

	myPublicIP string
	adminSeen  string

	// rate limits (function level `const` variables of the Pascal code)
	lastSendResumen, lastSendSumary, lastSendBlocks, lastSendUpdHeaders int64

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
	mnsRandomWait                                                       int64
	engineLastUpdate                                                    int64

	// MinPeers is the connection count that moves the node from state 1 to
	// 2. It is 3 on the real network (mpred.pas:499); tests lower it.
	MinPeers int

	// Dial opens outgoing connections; replaceable for tests.
	Dial func(addr string, timeout time.Duration) (net.Conn, error)

	Log func(ch, msg string)

	stop chan struct{}
	wg   sync.WaitGroup
	cmds chan string

	// CommandHook executes a console line from the process queue.
	CommandHook func(line string)
}

// NewEngine builds an engine around a node and wires the node hooks.
func NewEngine(n *node.Node) *Engine {
	e := &Engine{N: n, MinPeers: 3, bots: map[string]int64{}, ipCtl: map[string]int{},
		stop: make(chan struct{}), cmds: make(chan string, 256)}
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
		codec.Copy(crypto.MD5String(n.CFG.DataStr()), 0, 5) + " " +
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
		codec.IntToStr(int64(n.ChecksCount())) + " " + codec.Parameter(last.Solution, 2) + " " +
		codec.Parameter(last.Solution, 1) + " " + codec.Copy(n.Summary.Hash(), 0, 5) + " " +
		codec.Copy(n.GVTs.Hash(), 0, 5) + " " + codec.Copy(n.CFG.Hash(), 0, 5) + " " +
		codec.Copy(n.PSOs.FileHash(), 0, 5)
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
	if e.N.IsSeedNode(ip) {
		return
	}
	e.botsMu.Lock()
	e.bots[ip] = e.N.UTCTime()
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
