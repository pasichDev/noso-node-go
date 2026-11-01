package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// ValidProtocolCommands is masterpaskalform.pas:560-563. COMPAT: it is
// tested with a SUBSTRING match against the upper-cased command, so e.g. an
// empty command or "ORDER" inside a longer token is accepted.
const ValidProtocolCommands = "$PING$PONG$GETPENDING$NEWBL$GETRESUMEN$LASTBLOCK$GETCHECKS" +
	"$CUSTOMORDERADMINMSGNETREQ$REPORTNODE$GETMNS$BESTHASH$MNREPO$MNCHECK" +
	"GETMNSFILEMNFILEGETHEADUPDATE$GETSUMARY$GETGVTSGVTSFILE$SNDGVTGETCFGDATA" +
	"SETCFGDATA$GETPSOSPSOSFILE$NEWPSO$CLRPSO"

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
	ln, err := net.Listen("tcp", net.JoinHostPort(e.BindAddr, codec.IntToStr(int64(port))))
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
				// FIX(L2): only a closed listener ends the loop; a transient
				// error (out of descriptors) must not leave the node deaf.
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if !e.sleep(100 * time.Millisecond) {
					return
				}
				continue
			}
			cc := NewConn(c)
			if !e.trackConn(cc) {
				_ = c.Close()
				continue
			}
			e.wg.Add(1)
			go func() { defer e.wg.Done(); defer e.untrackConn(cc); e.handleIncoming(cc) }()
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

// maxPendingConns bounds the connections that have been accepted but are not
// (yet) peers: one-shot requests and greetings in progress (M8).
const maxPendingConns = 64

// trackConn registers an accepted connection so that Stop can end it; false
// when the node already holds too many.
func (e *Engine) trackConn(c *Conn) bool {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if len(e.conns) >= maxPendingConns {
		return false
	}
	e.conns[c] = struct{}{}
	return true
}

func (e *Engine) untrackConn(c *Conn) {
	e.connMu.Lock()
	delete(e.conns, c)
	e.connMu.Unlock()
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
	e.mu.Lock()
	keep := e.keepServer
	e.mu.Unlock()
	if !keep {
		closeWith(c, "Closing NODE")
		return
	}
	line, err := c.ReadLine(time.Second)
	if err != nil {
		e.logf("events", "connection from "+ip+": no greeting: "+err.Error())
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
	// The greeting carries the port the peer listens on (an addition of this
	// port: older nodes send nothing and are told apart by address alone).
	peerPort := int(codec.StrToIntDef(codec.Parameter(line, 4), -1))
	if peerPort < 1 || peerPort > 65535 {
		peerPort = -1
	}
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
	case "NSLPSO":
		closeWith(c, codec.IntToStr(int64(n.PTCPSO(codec.GetOpData(line)))))
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
	case e.isDenied(ip, peerPort):
		_ = c.Close()
	case abs64(n.UTCTime()-peerUTC) > 5 && n.MyLastBlock() >= 70000:
		closeWith(c, "WRONG_TIME")
	case e.slotForEndpoint(ip, peerPort) > 0:
		// FIX(M6): a second connection from a peer we already talk to (both
		// sides dialled at once) is refused, but the peer is not banned.
		e.logf("events", "duplicate connection refused: "+ip+":"+codec.IntToStr(int64(peerPort)))
		closeWith(c, node.PTCHeader(n)+"DUPLICATED")
	case codec.Copy(peerVersion, 1, 3) < codec.Copy(node.VersionRequired, 1, 3):
		closeWith(c, node.PTCHeader(n)+"OLDVERSION->REQUIRED_"+node.VersionRequired)
	default:
		sl := e.saveConnectionPort("CLI", ip, peerPort, c, -1)
		if sl == 0 {
			e.logf("events", "connection from "+ip+" refused: no free slot or duplicate")
			_ = c.Close()
			return
		}
		e.untrackConn(c) // from here on the slot owns the connection
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
	// FIX(L1): a reader closes its own connection, never the one that took
	// the slot number after it.
	closeMine := func() { e.closeSlotObj(sl, s) }
	go func() { // writer
		for {
			select {
			case l := <-s.out:
				if err := c.WriteLine(l); err != nil {
					closeMine()
					return
				}
			case <-s.closed:
				return
			}
		}
	}()
	lastActive := e.now()
	for {
		select {
		case <-s.closed:
			return
		case <-e.stop:
			closeMine()
			return
		default:
		}
		line, err := c.ReadLine(time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if client && lastActive+30 < e.now() {
					closeMine()
					return
				}
				continue
			}
			closeMine()
			return
		}
		if line == "" {
			continue
		}
		e.setBusy(sl, true)
		e.setLastPing(sl, e.nowStr())
		lastActive = e.now()
		ok := e.handleLine(sl, c, line, client)
		e.setBusy(sl, false)
		if !ok {
			closeMine()
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
// FIX(M-3): the summary, headers, GVT and PSO files are derived from the
// blocks, so they are never requested and a peer that pushes one is cut off.
var legacyFileLabels = map[string]bool{"RESUMENFILE": true, "SUMARYFILE": true, "GVTSFILE": true, "PSOSFILE": true}

var fileKinds = map[string]string{"BLOCKZIP": "BLOCKS"}

// handleLine processes one received line of a slot; false asks the caller
// to close the slot.
func (e *Engine) handleLine(sl int, c *Conn, line string, client bool) bool {
	n := e.N
	label := codec.Parameter(line, 0)
	if _, legacy := legacyFileLabels[label]; legacy && label == line {
		// a state file nobody asked for (they are never requested): cut off
		e.logf("events", "unsolicited "+label+" from "+e.peers.get(sl).IP)
		e.UpdateBotData(e.peers.get(sl).IP)
		return false
	}
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
		// Files go out through sendFile: bounded in number, one per slot, and
		// written by a goroutine of their own, so a slow reader costs this
		// connection only.
		key := e.peerKey(sl)
		switch codec.Parameter(line, 4) {
		case "$GETRESUMEN", "$GETSUMARY", "$GETPSOS", "$LASTBLOCK", "$GETGVTS":
			if !e.filePermit(codec.Parameter(line, 4), key) { // FIX(M-08, L-04): per-peer budget
				return true
			}
		}
		switch codec.Parameter(line, 4) {
		case "$GETRESUMEN":
			e.sendFile(sl, "RESUMENFILE", func() ([]byte, error) { return n.Headers.Bytes() })
			return true
		case "$GETSUMARY":
			e.sendFile(sl, "SUMARYFILE", func() ([]byte, error) { return n.Summary.Bytes() })
			return true
		case "$GETPSOS":
			e.sendFile(sl, "PSOSFILE", func() ([]byte, error) { return n.PSOs.Bytes() })
			return true
		case "$LASTBLOCK":
			first := codec.StrToIntDef(codec.Parameter(line, 5), -1) + 1
			e.sendFile(sl, "BLOCKZIP", func() ([]byte, error) { return e.zipBlocksFrom(first) })
			return true
		case "$GETGVTS":
			e.sendFile(sl, "GVTSFILE", func() ([]byte, error) { return n.GVTs.Bytes() })
			return true
		}
		if !strings.Contains(ValidProtocolCommands, codec.ASCIIUpper(codec.Parameter(line, 4))) {
			return false // unexpected line: the connection is closed
		}
	}
	if !e.lineBudget(sl, line) || !e.lineAllowed(sl, line) { // FIX(M-07): per-peer line, size and byte budgets
		return false
	}
	return e.addIncoming(sl, line)
}

// receiveFile reads one requested file. Only block archives are requested:
// the transfer is read without holding the engine lock, so a slow or silent
// peer costs only its own connection, and the blocks are checked one by one
// (proposer seal, signatures, state) by node.StageBlocks. FIX(C-03, H-06,
// H-11, M-3, H-3/H-4 of re2): no seed vote and no header record decides which
// blocks are taken.
func (e *Engine) receiveFile(sl int, c *Conn, kind string) bool {
	if kind != "BLOCKS" {
		return false
	}
	data, err := c.ReadStream(transferTime, maxBlockZip)
	if err != nil {
		e.syncMu.Lock()
		e.pullSlot = nil
		e.syncMu.Unlock()
		return false
	}
	return e.blocksReceived(sl, data)
}

// ---- client side -----------------------------------------------------------

// ConnectClient mirrors ConnectClient (mpred.pas:331-376). It returns the
// slot or 0.
func (e *Engine) ConnectClient(address, port string) int {
	p := int(codec.StrToIntDef(port, 8080))
	if e.isDenied(address, p) {
		return 0
	}
	sl := e.ReserveSlot()
	if sl == 0 {
		return 0
	}
	nc, err := e.Dial(net.JoinHostPort(address, codec.IntToStr(int64(p))), time.Second)
	if err != nil {
		e.CloseSlot(sl)
		return 0
	}
	c := NewConn(nc)
	e.saveConnectionPort("SER", address, p, c, sl)
	e.logf("events", "Connected TO: "+address)
	e.mu.Lock()
	myPort := 0
	if e.serverOn {
		myPort = e.serverPort
	}
	e.mu.Unlock()
	if err := c.WriteLine("PSK " + address + " " + node.MainnetVersion + node.NodeRelease + " " + e.N.UTCTimeStr() + " " +
		codec.IntToStr(int64(myPort))); err != nil {
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
			cmd := codec.ASCIIUpper(codec.Parameter(line, 4))
			peer := e.peers.get(sl)
			switch {
			case !IsValidProtocol(line) && !peer.Autentic:
				e.logf("console", "CONNECTION REJECTED: INVALID PROTOCOL -> "+peer.IP+"->"+line)
				if line != "Closing NODE" { // an old node that is not up to date says so; that is not abuse
					e.UpdateBotData(peer.IP)
				}
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
			case cmd == "$LASTBLOCK":
				e.sendBlocks(sl, line)
			case (n.BlockAge() < 10 || n.BlockAge() > 585):
				continue
			case cmd == "$GETPENDING":
				// FIX(H5/$GETMNS budget): both answers are one line per entry
				if e.filePermit("$GETPENDING", e.peerKey(sl)) {
					e.SendPendings(sl)
				}
			case cmd == "$GETMNS":
				if e.filePermit("$GETMNS", e.peerKey(sl)) {
					for _, m := range n.MNsList() {
						e.TextToSlot(sl, node.PTCHeader(n)+"$MNREPO "+node.StringFromMN(m))
					}
				}
			case cmd == "$GETRESUMEN":
				e.sendResumen(sl)
			case cmd == "$CUSTOM":
				if e.AddIPControl(peer.IP) < 100 {
					n.PTCCustom(codec.GetOpData(line))
				} else {
					e.spammer(sl, peer.IP)
				}
			case cmd == "$SNDGVT":
				// FIX(GAP-3): the dispatcher had no case for it (nor had the
				// original), so a GVT transfer was announced and dropped.
				if e.AddIPControl(peer.IP) < 100 {
					n.PTCSendGVT(codec.GetOpData(line))
				} else {
					e.spammer(sl, peer.IP)
				}
			case cmd == "$NEWPSO", cmd == "$CLRPSO":
				if e.AddIPControl(peer.IP) < 100 {
					n.PTCPSO(codec.GetOpData(line))
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
				// FIX(H-3): parse, bind to the current block and check the stake
				// before the report may use up the sender's IP slot or cost a
				// challenge; garbage or an unstaked key is dropped here.
				e.queueMNReport(line)
			case cmd == "$MNCHECK":
				if v := n.ValidateMNCheck(line); v != "" {
					e.OutgoingAdd(node.PTCHeader(n) + v)
				}
			case cmd == "$GETCHECKS":
				for _, c := range n.Checks() {
					e.TextToSlot(sl, e.ProtocolLine(14)+node.StringFromMNCheck(c))
				}
			case cmd == "GETMNSFILE":
				if e.filePermit("GETMNSFILE", e.peerKey(sl)) { // FIX(M-2): was unbudgeted
					e.PTCSendLine(sl, e.ProtocolLine(17)+" $"+n.MNFile.Load())
				}
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
		case "CUSTOM", "SNDGVT", node.PSONew, node.PSOClear:
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

// sendFile answers a file request. FIX(H-11, M3): the file is read and written
// by a goroutine of its own, so neither a big file nor a peer that reads
// slowly can stall the heartbeat; each slot has at most
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
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() { <-e.sendSlots; s.sending.Store(0) }()
		raw, err := get()
		if err != nil {
			raw = nil // Pascal sends an empty stream when the load failed
		}
		if err := s.conn.WriteStream(label, raw); err != nil {
			e.closeSlotObj(sl, s)
		}
	}()
}

func (e *Engine) sendResumen(sl int) {
	if !e.filePermit("$GETRESUMEN", e.peerKey(sl)) {
		return
	}
	e.sendFile(sl, "RESUMENFILE", func() ([]byte, error) { return e.N.Headers.Bytes() })
}

func (e *Engine) sendSumary(sl int) {
	if !e.filePermit("$GETSUMARY", e.peerKey(sl)) {
		return
	}
	e.sendFile(sl, "SUMARYFILE", func() ([]byte, error) { return e.N.Summary.Bytes() })
}

// sendBlocks mirrors PTC_SendBlocks: first block = parameter 5 + 1.
func (e *Engine) sendBlocks(sl int, line string) {
	if !e.filePermit("$LASTBLOCK", e.peerKey(sl)) {
		return
	}
	first := codec.StrToIntDef(codec.Parameter(line, 5), -1) + 1
	e.sendFile(sl, "BLOCKZIP", func() ([]byte, error) { return e.zipBlocksFrom(first) })
}

func (e *Engine) sendUpdateHeaders(sl int, line string) {
	if !e.filePermit("GETHEADUPDATE", e.peerKey(sl)) {
		return
	}
	blk := codec.StrToIntDef(codec.Parameter(line, 5), 0)
	e.PTCSendLine(sl, e.ProtocolLine(19)+" $"+e.N.Headers.LastHeadersString(int(blk)))
}

// fullHashOK reports whether h is the full hash the seeds voted for item idx.
// An empty vote never matches: without a majority nothing is accepted.
func (e *Engine) fullHashOK(idx int, h string) bool {
	v := e.GetConsensus(idx)
	return v != "" && v == h
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
