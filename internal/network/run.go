package network

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
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
	n := e.N
	e.mu.Lock()
	e.engineLastUpdate = n.UTCTime()
	build := e.buildNMSBlock
	e.mu.Unlock()
	if n.UTCTime() >= build && build > 0 && n.ConStatus() == 3 &&
		codec.IntToStr(n.MyLastBlock()) == e.GetConsensus(CLastBlock) {
		e.logf("events", "Starting construction of block "+codec.IntToStr(n.MyLastBlock()+1))
		_, err := n.BuildNewBlock(n.MyLastBlock()+1, build, n.MyLastBlockHash(), BuildMiner, BuildSolution)
		if err != nil {
			e.logf("exceps", "build block: "+err.Error())
		}
		e.mu.Lock()
		e.buildNMSBlock = 0
		e.mu.Unlock()
	}
	e.saveUpdatedFiles()
	e.drainCommands()
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

// Submit queues a console command line for the heartbeat (ProcessLinesAdd).
func (e *Engine) Submit(line string) {
	select {
	case e.cmds <- line:
	default:
	}
}

func (e *Engine) drainCommands() {
	for {
		select {
		case l := <-e.cmds:
			if e.CommandHook != nil {
				e.CommandHook(l)
			}
		default:
			return
		}
	}
}

// keepConnectLoop mirrors TThreadKeepConnect (masterpaskalform.pas:1401).
func (e *Engine) keepConnectLoop() {
	last := 0
	for {
		n := e.N
		try := true
		if e.TotalConnections() >= 99 || e.SyncedConnections() >= 3 {
			try = false
		}
		if n.BlockAge() < 10 || n.BlockAge() > 595 {
			try = false
		}
		if try {
			nodes := e.nodesList()
			if len(nodes) > 0 {
				last++
				if last >= len(nodes) {
					last = 0
				}
				nd := nodes[last]
				if e.GetSlotFromIP(nd.ip) == 0 && e.freeSlot() > 0 && nd.ip != n.Options().MNIP {
					e.ConnectClient(nd.ip, nd.port)
				}
			}
		}
		if !e.sleep(3 * time.Second) {
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
		if age >= 0 && age < 5 {
			e.lastConsensusTime = 0
		}
		if age >= 5 && age < 585 && e.lastConsensusTime+60 < n.UTCTime() {
			e.lastConsensusTime = n.UTCTime()
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
		if n.BlockAge() > 10 && lastIPVerify < now {
			lastIPVerify = consensus.NextBlockTimeStamp(now)
			if my := e.GetMyIP(); my != "" && my != o.MNIP && my != "Closing NODE" && my != "BANNED" && codec.IsValidIP(my) {
				e.logf("console", "Auto IP: updated to "+my)
				n.UpdateOptions(func(op *storageOptions) { op.MNIP = my })
			}
		}
		for n.WaitingMNsLen() > 0 {
			line := n.PopWaitingMN()
			if !n.IPMNAlreadyProcessed(line) {
				if info := n.CheckMNReport(line, n.MyLastBlock()); info != "" {
					e.OutgoingAdd(node.PTCHeader(n) + info)
				}
			}
		}
	}
}

// GetMyIP mirrors GetMiIP (mpred.pas:1084-1105): a random node reports the
// address it sees us from.
func (e *Engine) GetMyIP() string {
	nodes := e.nodesList()
	if len(nodes) == 0 {
		return ""
	}
	h := nodes[rand.Intn(len(nodes))]
	return e.RequestLine(h.ip, int(codec.StrToIntDef(h.port, 8080)), "GETMIIP")
}

// RunMNVerification mirrors nosomasternodes.pas:255-301: every reported
// masternode (except ours, with a valid public IP) is asked MNVER and the
// positive answers collected and signed.
func (e *Engine) RunMNVerification(block int64, synctus, localIP, pub, priv string) string {
	n := e.N
	list := n.MNsList()
	verified := make(chan string, len(list)+1)
	done := make(chan struct{}, len(list)+1)
	launched := 0
	for _, m := range list {
		if m.IP != localIP && codec.IsValidIP(m.IP) {
			launched++
			go func(m node.MNode) {
				defer func() { done <- struct{}{} }()
				time.Sleep(time.Second)
				var line string
				for try := 0; try < 3; try++ {
					line = e.RequestLine(m.IP, int(m.Port), "MNVER")
					if line != "" {
						break
					}
				}
				if codec.StrToBoolDef(codec.Parameter(line, 0), false) && codec.Parameter(line, 1) == synctus {
					verified <- m.IP + ";" + codec.IntToStr(int64(m.Port)) + ":"
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
	close(verified)
	vn := ""
	for v := range verified {
		vn += v
	}
	return localIP + " " + codec.IntToStr(block) + " " + n.Options().MNSign + " " + pub + " " + vn + " " +
		crypto.GetStringSigned(vn, priv)
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
		sl, ok := e.ValidSlotForSeed()
		if !ok {
			continue
		}
		p := e.peers.get(sl)
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

// UpdateTimeOffset mirrors GetTimeOffset (nosotime.pas:92-118) including the
// odd rotation of the server index.
func (e *Engine) UpdateTimeOffset(servers string) int64 {
	servers = codec.Trim(strings.ReplaceAll(servers, ":", " "))
	arr := strings.Split(servers, " ")
	if servers == "" {
		return 0
	}
	idx := rand.Intn(len(arr))
	var off int64
	for range arr {
		if idx >= len(arr) {
			idx = 0
		}
		if t := NetworkTimestamp(arr[idx]); t > 0 {
			off = t - time.Now().Unix()
			break
		}
		idx++
		if idx >= len(arr)-1 {
			idx = 0
		}
	}
	e.N.SetTimeOffset(off)
	return off
}
