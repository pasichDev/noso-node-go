package network

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// ValidProtocolCommands is masterpaskalform.pas:560-563. COMPAT: it is
// tested with a SUBSTRING match against the upper-cased command, so e.g. an
// empty command or "ORDER" inside a longer token is accepted.
const ValidProtocolCommands = "$PING$PONG$GETPENDING$NEWBL$GETRESUMEN$LASTBLOCK$GETCHECKS" +
	"$CUSTOMORDERADMINMSGNETREQ$REPORTNODE$GETMNS$BESTHASH$MNREPO$MNCHECK" +
	"GETMNSFILEMNFILEGETHEADUPDATE$GETSUMARY$GETGVTSGVTSFILE$SNDGVTGETCFGDATA" +
	"SETCFGDATA$GETPSOSPSOSFILE"

// IsValidProtocol mirrors nosonetwork.pas:379-383.
func IsValidProtocol(line string) bool {
	p := codec.Copy(line, 1, 4)
	return p == "PSK " || p == "NOS "
}

// ---- server side -----------------------------------------------------------

// StartServer mirrors ForceServer/StartServer (mpred.pas:160-222): the
// listener is opened on port and connections are handled.
func (e *Engine) StartServer(port int) error {
	e.mu.Lock()
	if e.serverOn {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	ln, err := net.Listen("tcp", net.JoinHostPort("", codec.IntToStr(int64(port))))
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.listener, e.serverOn, e.keepServer = ln, true, true
	e.serverPort = port
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		e.serverPort = tcp.Port
	}
	e.serverStart = e.N.UTCTime()
	e.mu.Unlock()
	e.logf("console", "Server ENABLED. Listening on port "+codec.IntToStr(int64(e.serverPort)))
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.wg.Add(1)
			go func() { defer e.wg.Done(); e.handleIncoming(NewConn(c)) }()
		}
	}()
	return nil
}

// StopServer mirrors StopServer (mpred.pas:225-240).
func (e *Engine) StopServer() {
	e.mu.Lock()
	ln := e.listener
	e.serverOn, e.keepServer = false, false
	e.listener = nil
	e.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for i := 1; i <= MaxConnections; i++ {
		if e.peers.get(i).Tipo == "CLI" {
			e.CloseSlot(i)
		}
	}
}

// ServerActive reports whether the listener is open.
func (e *Engine) ServerActive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.serverOn
}

// ServerAddr returns the listen address.
func (e *Engine) ServerAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listener == nil {
		return ""
	}
	return e.listener.Addr().String()
}

func closeWith(c *Conn, msg string) {
	if msg != "" {
		_ = c.WriteLine(msg)
	}
	_ = c.Close()
}

// handleIncoming mirrors IdTCPServer1Connect (masterpaskalform.pas:2623-2833)
// and then runs the Execute loop for accepted peers.
func (e *Engine) handleIncoming(c *Conn) {
	defer e.recoverPanic("incoming", c)
	ip := c.RemoteIP()
	n := e.N
	if e.BotExists(ip) {
		closeWith(c, "BANNED")
		return
	}
	if e.AddIPControl(ip) > 99 {
		closeWith(c, "")
		e.UpdateBotData(ip)
		e.logf("console", "IP spammer: "+ip)
		return
	}
	if n.ConStatus() < 3 && !n.IsSeedNode(ip) {
		closeWith(c, "Closing NODE")
		return
	}
	e.mu.Lock()
	keep := e.keepServer
	e.mu.Unlock()
	if !keep {
		closeWith(c, "Closing NODE")
		return
	}
	line, err := c.ReadLine(time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	switch codec.Parameter(line, 0) {
	case "NSLGVT", "GETZIPSUMARY", "NSLBLKORD", "NSLMNS", "NSLPENDFULL", "NODESTATUS":
		if !e.heavyOK(ip) { // FIX(M-08): costly requests are limited per peer
			closeWith(c, "")
			return
		}
	}
	miIP := codec.Parameter(line, 1)
	peerVersion := codec.Parameter(line, 2)
	peerUTC := codec.StrToInt64Def(codec.Parameter(line, 3), 0)
	switch codec.Parameter(line, 0) {
	case "NODESTATUS":
		closeWith(c, e.SignedStatus())
		return
	case "NSLORDER":
		closeWith(c, n.PTCOrder(line))
		return
	case "NSLCUSTOM":
		closeWith(c, codec.IntToStr(int64(n.PTCCustom(codec.GetOpData(line)))))
		return
	case "NSLSENDGVT":
		closeWith(c, codec.IntToStr(int64(n.PTCSendGVT(codec.GetOpData(line)))))
		return
	case "GETMIIP":
		closeWith(c, ip)
		return
	case "MNVER":
		closeWith(c, n.VerificationLine(codec.Parameter(line, 1)))
		return
	case "NSLBALANCE":
		closeWith(c, codec.IntToStr(n.AddressAvailable(codec.Parameter(line, 1))))
		return
	case "NSLPEND":
		closeWith(c, PendingRawInfo(n, false))
		return
	case "NSLPENDFULL":
		closeWith(c, PendingRawInfo(n, true))
		return
	case "NSLBLKORD":
		closeWith(c, n.NSLBlockOrders(line))
		return
	case "NSLTIME":
		closeWith(c, n.UTCTimeStr())
		return
	case "NSLMNS":
		closeWith(c, n.MNFile.Text())
		return
	case "NSLCFG":
		closeWith(c, n.CFG.DataStr())
		return
	case "NSLGVT":
		if raw, err := n.GVTs.Bytes(); err == nil && len(raw) > 0 {
			_ = c.WriteStream("GVTFILE "+codec.Copy(n.GVTs.Hash(), 0, 5), raw)
		}
		_ = c.Close()
		return
	case "GETZIPSUMARY":
		if raw, err := readFile(n.Lay.SummaryZip); err == nil && len(raw) > 0 {
			_ = c.WriteStream("ZIPSUMARY "+codec.Copy(n.Summary.Hash(), 0, 5), raw)
		}
		_ = c.Close()
		return
	}
	switch {
	case codec.Copy(line, 1, 4) != "PSK ":
		closeWith(c, "WRONG_PROTOCOL")
		e.UpdateBotData(ip)
	case ip == e.myPublicIP && ip != "":
		_ = c.Close()
	case abs64(n.UTCTime()-peerUTC) > 5 && n.MyLastBlock() >= 70000:
		closeWith(c, "WRONG_TIME")
	case e.GetSlotFromIP(ip) > 0:
		closeWith(c, node.PTCHeader(n)+"DUPLICATED")
		e.UpdateBotData(ip)
	case codec.Copy(peerVersion, 1, 3) < codec.Copy(node.VersionRequired, 1, 3):
		closeWith(c, node.PTCHeader(n)+"OLDVERSION->REQUIRED_"+node.VersionRequired)
	default:
		sl := e.SaveConnection("CLI", ip, c, -1)
		if sl == 0 {
			_ = c.Close()
			return
		}
		e.logf("events", "New Connection from: "+ip)
		_ = miIP // FIX(M-04): what a peer says about our address is ignored (masterpaskalform.pas:2821)
		e.runSlot(sl, c, false)
	}
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// runSlot starts the writer and runs the reader for an established slot.
// client is true for slots we dialled (TThreadClientRead), false for
// accepted ones (IdTCPServer1Execute).
func (e *Engine) runSlot(sl int, c *Conn, client bool) {
	defer e.recoverPanic("slot", c)
	e.peers.mu.Lock()
	s := e.peers.slots[sl]
	e.peers.mu.Unlock()
	if s == nil {
		return
	}
	go func() { // writer
		for {
			select {
			case l := <-s.out:
				if err := c.WriteLine(l); err != nil {
					e.CloseSlot(sl)
					return
				}
			case <-s.closed:
				return
			}
		}
	}()
	lastActive := e.N.UTCTime()
	for {
		select {
		case <-s.closed:
			return
		case <-e.stop:
			e.CloseSlot(sl)
			return
		default:
		}
		if !client && e.N.ConStatus() < 3 && !e.N.IsSeedNode(e.peers.get(sl).IP) {
			closeWith(c, "Closing NODE")
			e.CloseSlot(sl)
			return
		}
		line, err := c.ReadLine(time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if client && lastActive+30 < e.N.UTCTime() {
					e.CloseSlot(sl)
					return
				}
				continue
			}
			e.CloseSlot(sl)
			return
		}
		if line == "" {
			continue
		}
		e.setBusy(sl, true)
		e.setLastPing(sl, e.N.UTCTimeStr())
		lastActive = e.N.UTCTime()
		ok := e.handleLine(sl, c, line, client)
		e.setBusy(sl, false)
		if !ok {
			e.CloseSlot(sl)
			return
		}
	}
}

// Per-kind size limits for received files. FIX(H-11).
const (
	maxHeadersFile = 32 << 20
	maxSummaryFile = 128 << 20
	maxGVTFile     = 100 * 105
	maxPSOFile     = 16 << 20
	maxBlockZip    = 64 << 20
	maxMNText      = 1 << 20
	transferTime   = 120 * time.Second
)

// fileKinds maps the label line of a file transfer to the request kind it
// answers.
var fileKinds = map[string]string{"RESUMENFILE": "RESUMEN", "SUMARYFILE": "SUMARY", "GVTSFILE": "GVTS",
	"PSOSFILE": "PSOS", "BLOCKZIP": "BLOCKS"}

// handleLine processes one received line of a slot; false asks the caller
// to close the slot.
func (e *Engine) handleLine(sl int, c *Conn, line string, client bool) bool {
	n := e.N
	label := codec.Parameter(line, 0)
	if kind, isFile := fileKinds[label]; isFile && label == line {
		// FIX(C-02, C-03, H-05, H-06, H-11): a file is accepted only as the
		// answer to a request sent on this very connection; an unsolicited
		// one ends the connection (the original stored every push,
		// masterpaskalform.pas:953-1134, 2419-2469, 2584-2600).
		if !e.takeReply(sl, kind) {
			e.logf("events", "unsolicited "+label+" from "+e.peers.get(sl).IP)
			e.UpdateBotData(e.peers.get(sl).IP)
			return false
		}
		return e.receiveFile(sl, c, kind)
	}
	if len(line) > maxLineMNFile {
		return false
	}
	if !client {
		// IdTCPServer1Execute direct handlers (masterpaskalform.pas:2470-2582).
		ip := e.peers.get(sl).IP
		switch codec.Parameter(line, 4) {
		case "$GETRESUMEN", "$GETSUMARY", "$GETPSOS", "$LASTBLOCK", "$GETGVTS":
			if !e.filePermit(codec.Parameter(line, 4), ip) { // FIX(M-08, L-04): per-peer budget
				return true
			}
		}
		switch codec.Parameter(line, 4) {
		case "$GETRESUMEN":
			if raw, err := n.Headers.Bytes(); err == nil && len(raw) > 0 {
				_ = c.WriteStream("RESUMENFILE", raw)
			}
			return true
		case "$GETSUMARY":
			if raw, err := n.Summary.Bytes(); err == nil && len(raw) > 0 {
				_ = c.WriteStream("SUMARYFILE", raw)
			}
			return true
		case "$GETPSOS":
			if raw, err := n.PSOs.Bytes(); err == nil && len(raw) > 0 {
				_ = c.WriteStream("PSOSFILE", raw)
			}
			return true
		case "$LASTBLOCK":
			if z, err := n.ZipBlocks(codec.StrToIntDef(codec.Parameter(line, 5), 0)); err == nil {
				_ = c.WriteStream("BLOCKZIP", z)
			}
			return true
		case "$GETGVTS":
			if raw, err := n.GVTs.Bytes(); err == nil && len(raw) > 0 {
				_ = c.WriteStream("GVTSFILE", raw)
			}
			return true
		}
		if !strings.Contains(ValidProtocolCommands, strings.ToUpper(codec.Parameter(line, 4))) {
			return false // unexpected line: the connection is closed
		}
	}
	if !e.lineBudget(sl) || !e.lineAllowed(sl, line) { // FIX(M-07): per-peer line, size and byte budgets
		return false
	}
	return e.addIncoming(sl, line)
}

// fullHashOK reports whether h is the full hash the seeds voted for item idx.
// An empty vote never matches: without a majority nothing is accepted.
func (e *Engine) fullHashOK(idx int, h string) bool {
	v := e.GetConsensus(idx)
	return v != "" && v == h
}

// receiveFile reads and validates one requested file. FIX(C-03, H-06,
// H-11): the transfer is read without holding the engine lock, so a slow or
// silent peer costs only its own connection; a state file is stored only if
// its full 128-bit hash equals the value more than half of the configured
// seeds report, never because of what the sending peer says about itself.
func (e *Engine) receiveFile(sl int, c *Conn, kind string) bool {
	n := e.N
	var max int
	switch kind {
	case "RESUMEN":
		max = maxHeadersFile
	case "SUMARY":
		max = maxSummaryFile
	case "GVTS":
		max = maxGVTFile
	case "PSOS":
		max = maxPSOFile
	case "BLOCKS":
		max = maxBlockZip
	default:
		return false
	}
	data, err := c.ReadStream(transferTime, max)
	if err != nil {
		return false
	}
	h := crypto.IDHashBytes(data)
	var blocksOK bool
	if kind == "BLOCKS" {
		blocksOK = e.blocksMatchHeaders(data)
	}
	e.big.Lock()
	defer e.big.Unlock()
	switch kind {
	case "RESUMEN":
		if len(data)%types.ResumenSize != 0 || !e.fullHashOK(CFullHeaders, h) {
			return false
		}
		if !e.headersAgreeWithBlocks(data) { // FIX(H-05)
			return false
		}
		e.downloadHeaders = true
		n.Headers.Replace(data)
		n.Headers.SetHash()
		n.UpdateMyData()
		e.lastTimeRequestResumen = 0
		e.downloadHeaders = false
	case "SUMARY":
		if len(data)%types.SummarySize != 0 || !e.fullHashOK(CFullSummary, h) {
			return false
		}
		e.downloadSumary = true
		err := n.Summary.Replace(data)
		n.UpdateMyData()
		e.lastTimeRequestSumary = 0
		e.downloadSumary = false
		return err == nil
	case "GVTS":
		if len(data) != maxGVTFile || !e.fullHashOK(CFullGVTs, h) {
			return false
		}
		if n.GVTs.Replace(data) {
			n.GVTs.Reload()
		}
		e.lastTimeGVTsRequest = 0
	case "PSOS":
		if !storage.ValidPSOFile(data) || !e.fullHashOK(CFullPSO, h) {
			return false
		}
		if n.PSOs.Replace(data) {
			n.PSOs.Load()
			n.UpdateMyData()
		}
		e.lastTimePSOsRequest = 0
	case "BLOCKS":
		if !blocksOK {
			e.logf("events", "blocks refused: not the blocks the headers name")
			return false
		}
		e.downloadBlocks = true
		if _, err := n.StageBlocks(data); err != nil {
			e.logf("events", "blocks refused: "+err.Error())
			e.downloadBlocks = false
			return false
		}
		e.lastTimeRequestBlock = 0
		e.downloadBlocks = false
	}
	return true
}

// blocksMatchHeaders checks every block of a received archive against the
// header record of that number (which the seeds' full headers hash vouches
// for): the block file's identity hash must equal the recorded BlockHash.
// FIX(C-03): StageBlocks validated the contents but never tied a block to
// the headers, so a peer could supply a well-formed block that differs from
// the chain. Entries are bounded the same way StageBlocks bounds them.
func (e *Engine) blocksMatchHeaders(data []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(zr.File) > 128 {
		return false
	}
	hdr, err := e.N.Headers.Bytes()
	if err != nil {
		return false
	}
	var total uint64
	for _, f := range zr.File {
		name := f.Name
		if !strings.HasSuffix(name, ".blk") {
			return false
		}
		num := codec.StrToInt64Def(strings.TrimSuffix(name, ".blk"), -1)
		total += f.UncompressedSize64
		if num < 0 || f.UncompressedSize64 > 8<<20 || total > 64<<20 {
			return false
		}
		off := num * int64(types.ResumenSize)
		if off+int64(types.ResumenSize) > int64(len(hdr)) {
			return false // no header for this block
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 8<<20+1))
		rc.Close()
		if err != nil || len(raw) > 8<<20 {
			return false
		}
		r := types.DecodeResumen(hdr[off:])
		if int64(r.Block) != num || r.BlockHash != crypto.IDHashBytes(raw) {
			return false
		}
	}
	return true
}

// headersAgreeWithBlocks compares the newest headers with the blocks we hold.
func (e *Engine) headersAgreeWithBlocks(data []byte) bool {
	last := e.N.MyLastBlock()
	count := int64(len(data) / types.ResumenSize)
	for b := last; b > last-100 && b >= 0; b-- {
		if b >= count {
			return false // headers shorter than our chain
		}
		r := types.DecodeResumen(data[b*types.ResumenSize:])
		if int64(r.Block) != b || r.BlockHash != crypto.IDHashFile(e.N.Lay.BlockFile(b)) {
			return false
		}
	}
	return true
}

// ---- client side -----------------------------------------------------------

// ConnectClient mirrors ConnectClient (mpred.pas:331-376). It returns the
// slot or 0.
func (e *Engine) ConnectClient(address, port string) int {
	sl := e.ReserveSlot()
	if sl == 0 {
		return 0
	}
	p := int(codec.StrToIntDef(port, 8080))
	nc, err := e.Dial(net.JoinHostPort(address, codec.IntToStr(int64(p))), time.Second)
	if err != nil {
		e.CloseSlot(sl)
		return 0
	}
	c := NewConn(nc)
	e.SaveConnection("SER", address, c, sl)
	e.logf("events", "Connected TO: "+address)
	if err := c.WriteLine("PSK " + address + " " + node.MainnetVersion + node.NodeRelease + " " + e.N.UTCTimeStr()); err != nil {
		e.CloseSlot(sl)
		return 0
	}
	if err := c.WriteLine(e.ProtocolLine(3)); err != nil {
		e.CloseSlot(sl)
		return 0
	}
	e.wg.Add(1)
	go func() { defer e.wg.Done(); e.runSlot(sl, c, true) }()
	return sl
}

// ---- protocol line processing ---------------------------------------------

// ParseProtocolLines mirrors mpprotocol.pas:197-292: every queued line of
// every slot is dispatched.
func (e *Engine) ParseProtocolLines() {
	n := e.N
	for sl := 1; sl <= MaxConnections; sl++ {
		for {
			line, ok := e.popIncoming(sl)
			if !ok {
				break
			}
			cmd := strings.ToUpper(codec.Parameter(line, 4))
			peer := e.peers.get(sl)
			switch {
			case !IsValidProtocol(line) && !peer.Autentic:
				e.logf("console", "CONNECTION REJECTED: INVALID PROTOCOL -> "+peer.IP+"->"+line)
				e.UpdateBotData(peer.IP)
				e.CloseSlot(sl)
			case cmd == "DUPLICATED":
				e.logf("console", "You are already connected to "+peer.IP)
				e.CloseSlot(sl)
			case cmd == "OLDVERSION":
				e.logf("console", "You need update your node to connect to "+peer.IP)
				e.CloseSlot(sl)
			case cmd == "$PING":
				e.ProcessPing(line, sl, true)
			case cmd == "$PONG":
				e.ProcessPing(line, sl, false)
			case n.BlockAge() < 10 || n.BlockAge() > 585:
				continue
			case cmd == "$GETPENDING":
				e.SendPendings(sl)
			case cmd == "$GETMNS":
				for _, m := range n.MNsList() {
					e.TextToSlot(sl, node.PTCHeader(n)+"$MNREPO "+node.StringFromMN(m))
				}
			case cmd == "$GETRESUMEN":
				e.sendResumen(sl)
			case cmd == "$LASTBLOCK":
				e.sendBlocks(sl, line)
			case cmd == "$CUSTOM":
				if e.AddIPControl(peer.IP) < 100 {
					n.PTCCustom(codec.GetOpData(line))
				} else {
					e.spammer(sl, peer.IP)
				}
			case cmd == "ORDER":
				if e.AddIPControl(peer.IP) < 100 {
					if !n.OrderIDAlreadyProcessed(line) {
						n.PTCOrder(line)
					}
				} else {
					e.spammer(sl, peer.IP)
				}
			case cmd == "ADMINMSG":
				if e.AddIPControl(peer.IP) < 100 {
					e.ptcAdminMsg(line)
				}
			case cmd == "$MNREPO":
				n.AddWaitingMN(line)
			case cmd == "$MNCHECK":
				if v := n.ValidateMNCheck(line); v != "" {
					e.OutgoingAdd(node.PTCHeader(n) + v)
				}
			case cmd == "$GETCHECKS":
				for _, c := range n.Checks() {
					e.TextToSlot(sl, e.ProtocolLine(14)+node.StringFromMNCheck(c))
				}
			case cmd == "GETMNSFILE":
				e.PTCSendLine(sl, e.ProtocolLine(17)+" $"+n.MNFile.Load())
			case cmd == "GETCFGDATA":
				if sc, ok := n.StoredConfig(); ok { // only a signed configuration is ever served
					e.PTCSendLine(sl, e.ProtocolLine(31)+codec.IntToStr(sc.Seq)+" "+sc.Sig+" "+sc.Content)
				}
			case cmd == "MNFILE":
				if e.takeReply(sl, "MNFILE") { // FIX(H-06): only as an answer
					e.processMNFile(line)
				}
			case cmd == "SETCFGDATA":
				if e.takeReply(sl, "CFG") { // FIX(C-01): only as an answer
					e.processCFGData(line)
				}
			case cmd == "GETHEADUPDATE":
				e.sendUpdateHeaders(sl, line)
			case cmd == "HEADUPDATE":
				if e.takeReply(sl, "HEADUPD") { // FIX(H-05)
					e.headUpdate(line)
				}
			case cmd == "$GETSUMARY":
				e.sendSumary(sl)
			case cmd == "$GETPSOS":
				e.sendFile(sl, "PSOSFILE", func() ([]byte, error) { return n.PSOs.Bytes() })
			case cmd == "$GETGVTS":
				e.sendFile(sl, "GVTSFILE", func() ([]byte, error) { return n.GVTs.Bytes() })
			default:
				e.logf("console", "Unknown command () in slot: ("+line+") "+codec.IntToStr(int64(sl)))
			}
		}
	}
}

func (e *Engine) spammer(sl int, ip string) {
	e.UpdateBotData(ip)
	e.logf("console", "IP spammer: "+ip)
	e.CloseSlot(sl)
}

// SendPendings mirrors SendPendingsToPeer (nosonetwork.pas:217-258): CUSTOM
// and SNDGVT orders are sent one per line with a '$' prefix, TRFR orders
// are grouped by OrderLines into one ORDER line.
func (e *Engine) SendPendings(sl int) {
	n := e.N
	enc := node.PTCHeader(n)
	textOrder := enc + "ORDER "
	for _, o := range n.PendingCopy() {
		text := stringFromOrder(o)
		switch o.OrderType {
		case "CUSTOM", "SNDGVT":
			e.TextToSlot(sl, enc+"$"+text)
		case "TRFR":
			if o.TrxLine == 1 {
				textOrder += codec.IntToStr(int64(o.OrderLines)) + " "
			}
			textOrder += "$" + text + " "
			if o.OrderLines == o.TrxLine {
				e.TextToSlot(sl, textOrder[:len(textOrder)-1])
				textOrder = enc + "ORDER "
			}
		}
	}
}

// sendFile answers a file request. FIX(H-11): the file is read here (the
// caller holds the heartbeat lock) but written by a goroutine of its own, so
// a peer that reads slowly cannot stall the heartbeat; each slot has at most
// one transfer going and the node at most maxSendsAtOnce.
func (e *Engine) sendFile(sl int, label string, get func() ([]byte, error)) {
	s := e.slotObj(sl)
	if s == nil || s.conn == nil || !s.sending.CompareAndSwap(0, 1) {
		return
	}
	select {
	case e.sendSlots <- struct{}{}:
	default:
		s.sending.Store(0)
		return
	}
	raw, err := get()
	if err != nil {
		raw = nil // Pascal sends an empty stream when the load failed
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() { <-e.sendSlots; s.sending.Store(0) }()
		if err := s.conn.WriteStream(label, raw); err != nil {
			e.CloseSlot(sl)
		}
	}()
}

func (e *Engine) sendResumen(sl int) {
	if !e.filePermit("$GETRESUMEN", e.peers.get(sl).IP) {
		return
	}
	e.sendFile(sl, "RESUMENFILE", func() ([]byte, error) { return e.N.Headers.Bytes() })
}

func (e *Engine) sendSumary(sl int) {
	if !e.filePermit("$GETSUMARY", e.peers.get(sl).IP) {
		return
	}
	e.sendFile(sl, "SUMARYFILE", func() ([]byte, error) { return e.N.Summary.Bytes() })
}

// sendBlocks mirrors PTC_SendBlocks: first block = parameter 5 + 1.
func (e *Engine) sendBlocks(sl int, line string) {
	if !e.filePermit("$LASTBLOCK", e.peers.get(sl).IP) {
		return
	}
	first := codec.StrToIntDef(codec.Parameter(line, 5), -1) + 1
	e.sendFile(sl, "BLOCKZIP", func() ([]byte, error) { return e.N.ZipBlocks(first) })
}

func (e *Engine) sendUpdateHeaders(sl int, line string) {
	if !e.filePermit("GETHEADUPDATE", e.peers.get(sl).IP) {
		return
	}
	blk := codec.StrToIntDef(codec.Parameter(line, 5), 0)
	e.PTCSendLine(sl, e.ProtocolLine(19)+" $"+e.N.Headers.LastHeadersString(int(blk)))
}

// processMNFile mirrors PTC_ProcessMNFileIncoming: accepted only when the
// full hash of the text + CR LF equals the one the seeds voted for (H-06;
// the original compared 5 characters).
func (e *Engine) processMNFile(line string) {
	text := codec.ExtractMNsText(line)
	if e.fullHashOK(CFullMNs, crypto.IDHash(text+"\r\n")) {
		e.N.MNFile.Save(text)
	}
}

// processCFGData accepts a signed configuration: `SETCFGDATA $<seq> <sig>
// <content>`. FIX(C-01): the original compared 5 hex characters of an MD5
// (mpprotocol.pas:1064-1080).
func (e *Engine) processCFGData(line string) {
	parts := strings.SplitN(codec.ExtractMNsText(line), " ", 3)
	if len(parts) != 3 {
		return
	}
	seq, ok := codec.StrToInt64(parts[0])
	if !ok {
		return
	}
	if err := e.N.AcceptConfig(node.SignedConfig{Seq: seq, Sig: parts[1], Content: parts[2]}); err != nil {
		e.logf("events", "configuration refused: "+err.Error())
		return
	}
	e.logf("events", "Noso CFG updated!")
}

// headUpdate mirrors PTC_HeadUpdate (mpprotocol.pas:1127-1172). FIX(H-05):
// the new records are appended to a copy in memory; the headers file is
// replaced only when the result has the full hash the seeds voted for and
// agrees with the blocks we hold. The original appended first and compared
// afterwards, leaving junk records on disk.
func (e *Engine) headUpdate(line string) {
	n := e.N
	want := e.GetConsensus(CFullHeaders)
	if want == "" || n.Headers.Hash() == want {
		return
	}
	cur, err := n.Headers.Bytes()
	if err != nil || len(cur)%types.ResumenSize != 0 {
		return
	}
	next := int64(n.Headers.LastBlock()) + 1
	cand := append([]byte(nil), cur...)
	content := codec.ExtractMNsText(line)
	for i := int64(0); i < 2000; i++ {
		h := codec.Parameter(content, i)
		if h == "" {
			break
		}
		h = strings.ReplaceAll(h, ":", " ")
		num := codec.StrToIntDef(codec.Parameter(h, 0), 0)
		if num != next {
			continue
		}
		bh, sh := codec.Parameter(h, 1), codec.Parameter(h, 2)
		if len(bh) != 32 || len(sh) != 32 {
			break
		}
		cand = append(cand, types.Resumen{Block: int32(num), BlockHash: bh, SumHash: sh}.Encode()...)
		next++
	}
	if crypto.IDHashBytes(cand) != want || !e.headersAgreeWithBlocks(cand) {
		e.forceCompleteHeadersDownload = true
		e.logf("console", "Update headers failed")
		return
	}
	n.Headers.Replace(cand)
	n.Headers.SetHash()
	e.logf("console", "Headers Updated!")
	e.forceCompleteHeadersDownload = false
}

// ptcAdminMsg handles `ADMINMSG <seq> <expiryBlock> <text_with_underscores>
// <signature>`. FIX(H-02, H-03, C-08): the signature covers a sequence
// number and an expiry height, the key comes from the configuration, and
// the only directives that exist change the node configuration (no update,
// no restart, no fund movement).
func (e *Engine) ptcAdminMsg(line string) {
	seq, ok1 := codec.StrToInt64(codec.Parameter(line, 5))
	exp, ok2 := codec.StrToInt64(codec.Parameter(line, 6))
	text := strings.ReplaceAll(codec.Parameter(line, 7), "_", " ")
	if !ok1 || !ok2 {
		return
	}
	if _, err := e.N.AcceptDirective(seq, exp, text, codec.Parameter(line, 8)); err != nil {
		e.logf("events", "directive refused: "+err.Error())
		return
	}
	e.SetNodesArray(e.N.CFG.Param(1))
	e.OutgoingAdd(line)
}

// recoverPanic keeps a malformed input from taking the node down and closes
// the offending connection. FIX(M-06, M-15): the original had no guard around
// its thread bodies.
func (e *Engine) recoverPanic(where string, c *Conn) {
	if r := recover(); r != nil {
		e.logf("exceps", fmt.Sprintf("panic in %s: %v", where, r))
		if c != nil {
			_ = c.Close()
		}
	}
}
