package network

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

type storageOptions = storage.Options

// BuildMiner is the address that receives the proof-of-work part of every
// block built by this node. COMPAT: masterpaskalform.pas:2039 hard-codes the
// project funds address as miner and "!!!!!!!!!100000000" as solution.
const (
	BuildMiner    = consensus.ProjectFunds
	BuildSolution = "!!!!!!!!!100000000"
)

// Start launches the background goroutines (heartbeat, connection keeper,
// masternode worker, consensus poller).
func (e *Engine) Start() {
	e.SetNodesArray(e.N.CFG.Param(1))
	e.mnsRandomWait = int64(rand.Intn(21))
	// FIX(C2): the listener opens at start when the node is set to serve, not
	// after a vote has declared the node up to date; the old order made it
	// impossible to bring a new network up without a console trick.
	if o := e.N.Options(); o.AutoServer && !e.ServerActive() {
		if err := e.StartServer(int(codec.StrToIntDef(o.MNPort, 8080))); err != nil {
			e.logf("console", "Unable to start the server: "+err.Error())
		}
	}
	e.spawn(e.heartbeatLoop)
	e.spawn(e.keepConnectLoop)
	e.spawn(e.mnLoop)
	e.spawn(e.consensusLoop)
	e.spawn(e.restartTimerLoop)
}

// Stop shuts everything down.
func (e *Engine) Stop() {
	select {
	case <-e.stop:
		return
	default:
		close(e.stop)
	}
	e.StopServer()
	for i := 1; i <= MaxConnections; i++ {
		e.CloseSlot(i)
	}
	e.connMu.Lock() // one-shot transfers that are not peers (M8)
	for c := range e.conns {
		_ = c.Close()
	}
	e.connMu.Unlock()
	e.wg.Wait()
}

func (e *Engine) spawn(f func()) {
	e.wg.Add(1)
	go func() { defer e.wg.Done(); f() }()
}

func (e *Engine) sleep(d time.Duration) bool {
	select {
	case <-e.stop:
		return false
	case <-time.After(d):
		return true
	}
}

// Tick runs one heartbeat iteration (masterpaskalform.pas:2031-2069).
func (e *Engine) Tick() {
	e.big.Lock()
	defer e.big.Unlock()
	n := e.N
	e.mu.Lock()
	e.engineLastUpdate = n.UTCTime()
	build := e.buildNMSBlock
	canBuild := e.canBuild
	e.mu.Unlock()
	// FIX(C1, H-5, F-2): the builder needs to be connected to enough peers it
	// has heard from, not to hold the block the seeds voted for and not to be
	// "caught up" with whatever height a peer claims: a claim is an
	// unauthenticated number and must not stop a proposer. It builds on its
	// own verified state; a branch that turns out better wins by its weight.
	if n.Options().BuildBlocks && n.InTurn(build) && n.UTCTime() >= build && build > 0 && (n.ConStatus() == 3 || canBuild) {
		e.logf("events", "Starting construction of block "+codec.IntToStr(n.MyLastBlock()+1))
		_, err := n.BuildNewBlock(n.MyLastBlock()+1, build, n.MyLastBlockHash(), BuildMiner, BuildSolution)
		if err != nil {
			// FIX: the build time is kept after a failure (Pascal clears it
			// only on success, mpblock.pas:391), so the build is retried.
			e.logf("exceps", "build block: "+err.Error())
		} else {
			e.mu.Lock()
			e.buildNMSBlock = 0
			e.mu.Unlock()
		}
	}
	e.saveUpdatedFiles()
	e.ReadClientsCheck()
	e.ParseProtocolLines()
	e.VerifyConnectionStatus()
	now := n.UTCTime()
	if now%60 == 0 && e.lastIPsClear != now {
		e.ClearIPControls()
	}
	if now%3600 == 3590 && e.lastBotClear != now && e.ServerActive() {
		e.DeleteBots()
	}
}

func (e *Engine) saveUpdatedFiles() {}

func (e *Engine) heartbeatLoop() {
	for e.sleep(200 * time.Millisecond) {
		e.Tick()
	}
}

// restartTimerLoop mirrors TForm1.RestartTimerEjecutar (1 s): while the
// block is not about to close, the next build time is the next boundary.
func (e *Engine) restartTimerLoop() {
	for e.sleep(time.Second) {
		n := e.N
		e.mu.Lock()
		if n.BlockAge() < 590 && e.buildNMSBlock < n.UTCTime() {
			e.buildNMSBlock = consensus.NextBlockTimeStamp(n.UTCTime())
			e.logf("events", "Next block time set to: "+codec.IntToStr(e.buildNMSBlock))
		}
		e.mu.Unlock()
	}
}

// BuildTime returns the pending block timestamp.
func (e *Engine) BuildTime() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.buildNMSBlock
}

// keepConnectLoop mirrors TThreadKeepConnect (masterpaskalform.pas:1401). It
// dials every configured node that is not connected yet, one per pass,
// starting at a rotating position. A node is a host and a port: several
// nodes may run on one machine. A node never dials itself.
func (e *Engine) keepConnectLoop() {
	last := 0
	for {
		if e.TotalConnections() < 99 {
			nodes := e.nodesList()
			for k := 0; k < len(nodes); k++ {
				last = (last + 1) % len(nodes)
				nd := nodes[last]
				port := int(codec.StrToIntDef(nd.port, 8080))
				if e.isSelf(nd.ip, nd.port) {
					continue
				}
				if e.slotForEndpoint(nd.ip, port) == 0 && e.freeSlot() > 0 {
					e.ConnectClient(nd.ip, nd.port)
					break
				}
			}
		}
		// jitter keeps two nodes from dialling each other at the same moment
		if !e.sleep(2*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond) {
			return
		}
	}
}

func (e *Engine) freeSlot() int {
	for i := 1; i <= MaxConnections; i++ {
		if e.peers.get(i).Tipo == "" {
			return i
		}
	}
	return 0
}

type hostPort struct{ ip, port string }

// nodesList mirrors FillNodeList: seeds plus the verificators text.
func (e *Engine) nodesList() []hostPort {
	src := e.N.CFG.Param(1) + e.N.MNFile.VerificatorsText()
	src = strings.ReplaceAll(src, ":", " ")
	var out []hostPort
	for i := int64(0); ; i++ {
		item := strings.ReplaceAll(codec.Parameter(src, i), ";", " ")
		ip := codec.Parameter(item, 0)
		if ip == "" {
			break
		}
		if ip == "null" { // the empty marker of the configuration, not a host
			continue
		}
		out = append(out, hostPort{ip, codec.IntToStr(codec.StrToIntDef(codec.Parameter(item, 1), 8080))})
	}
	return out
}

// NodesList returns "ip:port" strings of the known nodes.
func (e *Engine) NodesList() []string {
	var out []string
	for _, h := range e.nodesList() {
		out = append(out, h.ip+":"+h.port)
	}
	return out
}

// consensusLoop mirrors TThreadAutoConsensus (nosoconsensus.pas:126-137).
func (e *Engine) consensusLoop() {
	for e.sleep(100 * time.Millisecond) {
		n := e.N
		age := n.BlockAge()
		e.consMu.Lock()
		if age >= 0 && age < 5 {
			e.lastConsensusTime = 0
		}
		due := age >= 5 && age < 585 && e.lastConsensusTime+60 < n.UTCTime()
		if due {
			e.lastConsensusTime = n.UTCTime()
		}
		e.consMu.Unlock()
		if due {
			e.CalculateConsensus()
		}
	}
}

// mnLoop mirrors TUpdateMNs (masterpaskalform.pas:1199-1249).
func (e *Engine) mnLoop() {
	var lastIPVerify int64
	for e.sleep(10 * time.Millisecond) {
		n := e.N
		o := n.Options()
		now := n.UTCTime()
		if now%10 == 0 && n.IsValidator(o.MNIP) && n.BlockAge() > 500+e.mnsRandomWait/4 && !n.MyCheckDone() &&
			n.BlockAge() < 575 && e.lastRunMNVerification != now && n.ConStatus() == 3 {
			e.lastRunMNVerification = now
			w := n.Wallet.At(n.Wallet.IndexOf(o.MNSign))
			e.OutgoingAdd(e.ProtocolLine(14) + e.RunMNVerification(n.MyLastBlock(), n.SyncTus(), o.MNIP, w.PublicKey, w.PrivateKey))
		}
		if o.MNAutoIP && n.BlockAge() > 10 && lastIPVerify < now {
			lastIPVerify = consensus.NextBlockTimeStamp(now)
			if my := e.GetMyIP(); my != "" && my != o.MNIP && my != "Closing NODE" && my != "BANNED" && codec.IsValidIP(my) {
				e.logf("console", "Auto IP: updated to "+my)
				n.UpdateOptions(func(op *storageOptions) { op.MNIP = my })
				_ = n.SaveOptions() // FIX: saveUpdatedFiles was a no-op
			}
		}
		for n.WaitingMNsLen() > 0 {
			select {
			case <-e.stop: // FIX(M-1): shutdown does not wait for a backlog of challenges
				return
			default:
			}
			line := n.PopWaitingMN()
			if !n.IPMNAlreadyProcessed(line) && e.challengeReport(line) {
				if info := n.CheckMNReport(line, n.MyLastBlock()); info != "" {
					e.OutgoingAdd(node.PTCHeader(n) + info)
				}
			}
		}
	}
}

// maxWaitingMNs bounds the queue of reports waiting for a challenge.
const maxWaitingMNs = 256

// queueMNReport admits a received $MNREPO line to the challenge queue. FIX
// (H-3): the report is parsed, bound to the current block and its stake
// checked before anything else: before the sender's IP is marked as received
// (so garbage cannot burn a masternode's slot) and before the node dials the
// IP the report names (so an unstaked key cannot make the node dial anywhere).
func (e *Engine) queueMNReport(line string) {
	n := e.N
	p := strings.IndexByte(line, '$')
	if p < 0 {
		return
	}
	m, ok := node.ParseMNode(line[p:])
	if !ok {
		return
	}
	block := n.MyLastBlock()
	if int64(m.First) != block || int64(m.Last) != block || !n.IsLegitNewNode(m, block) {
		return
	}
	if n.WaitingMNsLen() >= maxWaitingMNs {
		return
	}
	// FIX(F-5): one queued report per fund and block. A staked key could
	// otherwise sign reports naming any number of other nodes' IPs; each one
	// that is queued uses up that IP's slot for the block.
	e.mnMu.Lock()
	if e.mnFundsBlock != block {
		e.mnFundsBlock, e.mnFunds = block, map[string]bool{}
	}
	if e.mnFunds[m.Fund] {
		e.mnMu.Unlock()
		return
	}
	e.mnFunds[m.Fund] = true
	e.mnMu.Unlock()
	n.AddWaitingMN(line)
}

// GetMyIP asks up to three known nodes which address they see us from and
// returns it only when at least two agree. FIX(M-04): the original took the
// answer of one random node (mpred.pas:1084-1105) and also trusted peers'
// greeting lines.
func (e *Engine) GetMyIP() string {
	nodes := e.nodesList()
	rand.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
	votes := map[string]int{}
	for i, h := range nodes {
		if i >= 3 {
			break
		}
		if ip := e.RequestLine(h.ip, int(codec.StrToIntDef(h.port, 8080)), "GETMIIP"); codec.IsValidIP(ip) {
			votes[ip]++
		}
	}
	for ip, v := range votes {
		if v >= 2 {
			return ip
		}
	}
	return ""
}

// RunMNVerification asks every other reported masternode MNVER with a fresh
// nonce and collects only answers signed by that masternode's sign key.
// FIX(M-05, C-07): the original accepted any text starting with "True"
// (nosomasternodes.pas:181-244) and signed the result with the legacy scheme.
func (e *Engine) RunMNVerification(block int64, synctus, localIP, pub, priv string) string {
	n := e.N
	list := n.MNsList()
	var vmu sync.Mutex
	var verifiedList []string
	done := make(chan struct{}, len(list)+1)
	launched := 0
	for _, m := range list {
		if m.IP != localIP && codec.IsValidIP(m.IP) {
			launched++
			go func(m node.MNode) {
				defer func() { done <- struct{}{} }()
				time.Sleep(time.Second)
				nonce := randomNonce()
				var line string
				for try := 0; try < 3; try++ {
					line = e.RequestLine(m.IP, int(m.Port), "MNVER "+nonce)
					if line != "" {
						break
					}
				}
				if node.CheckVerificationLine(line, nonce, synctus, m) {
					vmu.Lock()
					verifiedList = append(verifiedList, m.IP+";"+codec.IntToStr(int64(m.Port))+":")
					vmu.Unlock()
				}
			}(m)
		}
	}
	deadline := time.After(25 * time.Second)
	for i := 0; i < launched; i++ {
		select {
		case <-done:
		case <-deadline:
			i = launched
		}
	}
	// FIX: the list is copied, not closed, so a worker still running after
	// the deadline cannot panic on a closed channel.
	vmu.Lock()
	vn := strings.Join(verifiedList, "")
	vmu.Unlock()
	c := node.MNCheck{ValidatorIP: localIP, Block: int32(block), SignAddress: n.Options().MNSign, PubKey: pub, ValidNodes: vn}
	c.Signature = crypto.SignCanonical(priv, "MNCHECK1", node.MNCheckFields(c)...)
	return node.StringFromMNCheck(c)
}

func randomNonce() string {
	b := make([]byte, 12)
	_, _ = cryptorand.Read(b)
	return hex.EncodeToString(b)
}

// SendOrderToNode mirrors mpred.pas:1135-1173: the order line is handed to
// a random synced peer's listening port. Errors: ERROR 19 (connect), 20
// (not updated), 21 (no answer).
func (e *Engine) SendOrderToNode(line string) string {
	if e.N.ConStatus() < 3 {
		return "ERROR 20"
	}
	res := ""
	for try := 0; try < 3; try++ {
		sl, ok := e.anyPeerSlot()
		if !ok {
			continue
		}
		p := e.peers.get(sl)
		if p.ListeningPort <= 0 {
			continue
		}
		res = e.RequestLine(p.IP, p.ListeningPort, line)
		if res != "" {
			break
		}
		res = "ERROR 19"
	}
	if res == "" {
		res = "ERROR 21"
	}
	return res
}

// ---- SNTP -------------------------------------------------------------------

// NetworkTimestamp mirrors GetNetworkTimestamp (nosotime.pas:63-79): one
// SNTP query; 0 on any failure.
func NetworkTimestamp(host string) int64 {
	c, err := net.DialTimeout("udp", net.JoinHostPort(host, "123"), 500*time.Millisecond)
	if err != nil {
		return 0
	}
	defer c.Close()
	req := make([]byte, 48)
	req[0] = 0x1b // LI 0, VN 3, mode 3 (client)
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write(req); err != nil {
		return 0
	}
	resp := make([]byte, 48)
	if n, err := c.Read(resp); err != nil || n < 48 {
		return 0
	}
	secs := int64(binary.BigEndian.Uint32(resp[40:44]))
	const ntpToUnix = 2208988800
	if secs <= ntpToUnix {
		return 0
	}
	return secs - ntpToUnix
}

// MaxClockCorrection is the largest NTP correction accepted (seconds).
const MaxClockCorrection = 120

// MedianOffset reduces NTP offsets to their median; it needs at least two
// answers and refuses corrections above MaxClockCorrection. FIX(M-03): the
// original trusted the first NTP reply with no bound (nosotime.pas:92-118).
func MedianOffset(offsets []int64) (int64, bool) {
	if len(offsets) < 2 {
		return 0, false
	}
	s := append([]int64(nil), offsets...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	if m > MaxClockCorrection || m < -MaxClockCorrection {
		return 0, false
	}
	return m, true
}

// UpdateTimeOffset queries up to five of the configured NTP servers and
// applies the median offset.
func (e *Engine) UpdateTimeOffset(servers string) int64 {
	servers = codec.Trim(strings.ReplaceAll(servers, ":", " "))
	if servers == "" {
		return 0
	}
	arr := strings.Split(servers, " ")
	rand.Shuffle(len(arr), func(i, j int) { arr[i], arr[j] = arr[j], arr[i] })
	if len(arr) > 5 {
		arr = arr[:5]
	}
	res := make(chan int64, len(arr))
	for _, h := range arr {
		go func(h string) {
			if t := NetworkTimestamp(h); t > 0 {
				res <- t - time.Now().Unix()
			} else {
				res <- math.MinInt64
			}
		}(h)
	}
	var offs []int64
	for range arr {
		if o := <-res; o != math.MinInt64 {
			offs = append(offs, o)
		}
	}
	m, ok := MedianOffset(offs)
	if !ok {
		return e.N.UTCTime() - time.Now().Unix()
	}
	e.N.SetTimeOffset(m)
	return m
}

// challengeReport proves that the reporter controls the IP it names: the node
// at that address must answer an MNVER challenge (fresh nonce) with a
// signature of the report's sign key. FIX(C-07): a report was believed on
// the signature of the funds key alone, so anyone with stake could list any
// IP. This is the verification that is on by default, whether or not any
// registered validator exists. Our own report is not challenged.
func (e *Engine) challengeReport(line string) bool {
	p := strings.IndexByte(line, '$')
	if p < 0 {
		p = 0
	}
	m, ok := node.ParseMNode(line[p:])
	if !ok {
		return false
	}
	// FIX(M-1): only a report of our own masternode (same IP, sign and funds
	// address as configured) is believed without a challenge; the IP alone let
	// a funded stranger take this node's slot.
	if o := e.N.Options(); m.IP == o.MNIP && m.Sign == o.MNSign && m.Fund == o.MNFunds {
		return true
	}
	nonce := randomNonce()
	var ans string
	for try := 0; try < 2 && ans == ""; try++ {
		ans = e.RequestLine(m.IP, int(m.Port), "MNVER "+nonce)
	}
	return node.CheckVerificationLine(ans, nonce, e.N.SyncTus(), m)
}
