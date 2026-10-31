package network

import (
	"net"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
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
	miIP := codec.Parameter(line, 1)
	peerVersion := codec.Parameter(line, 2)
	peerUTC := codec.StrToInt64Def(codec.Parameter(line, 3), 0)
	switch codec.Parameter(line, 0) {
	case "NODESTATUS":
		closeWith(c, "NODESTATUS "+e.NodeStatusString())
		return
	case "NSLORDER":
		closeWith(c, n.PTCOrder(line))
		return
	case "NSLCUSTOM":
		closeWith(c, codec.IntToStr(int64(n.PTCCustom(codec.GetOpData(line)))))
		return
	case "NSLSENDGVT":
		closeWith(c, codec.IntToStr(int64(n.PTCSendGVT(line))))
		return
	case "GETMIIP":
		closeWith(c, ip)
		return
	case "MNVER":
		closeWith(c, n.VerificationLine(ip))
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
		if codec.IsValidIP(miIP) {
			e.myPublicIP = miIP
		}
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

// handleLine processes one received line of a slot; false asks the caller
// to close the slot.
func (e *Engine) handleLine(sl int, c *Conn, line string, client bool) bool {
	n := e.N
	label := codec.Parameter(line, 0)
	recv := func() ([]byte, bool) {
		data, err := c.ReadStream(10 * time.Second)
		return data, err == nil
	}
	switch {
	case label == "RESUMENFILE":
		data, ok := recv()
		if !ok || len(data)%70 != 0 { // hardening: whole records only
			return false
		}
		e.downloadHeaders = true
		saved := n.Headers.Replace(data)
		n.UpdateMyData()
		e.lastTimeRequestResumen = 0
		e.downloadHeaders = false
		return saved || !client
	case label == "SUMARYFILE" && client:
		data, ok := recv()
		if !ok || len(data)%106 != 0 {
			return false
		}
		e.downloadSumary = true
		err := n.Summary.Replace(data)
		n.UpdateMyData()
		e.lastTimeRequestSumary = 0
		e.downloadSumary = false
		return err == nil
	case label == "PSOSFILE":
		data, ok := recv()
		if !ok {
			return false
		}
		if n.PSOs.Replace(data) {
			n.PSOs.Load()
			n.UpdateMyData()
		}
		e.lastTimePSOsRequest = 0
		return true
	case label == "GVTSFILE" && client:
		data, ok := recv()
		if !ok || len(data)%105 != 0 {
			return false
		}
		saved := n.GVTs.Replace(data)
		if saved {
			n.GVTs.Reload()
		}
		e.lastTimeGVTsRequest = 0
		return saved
	case line == "BLOCKZIP":
		data, ok := recv()
		if !ok {
			return false
		}
		e.downloadBlocks = true
		if cnt, err := n.UnzipBlocks(data); err == nil && cnt >= 0 {
			n.SetMyLastBlock(n.Blocks.LastUpdated())
			n.UpdateMyData()
		}
		e.lastTimeRequestBlock = 0
		e.downloadBlocks = false
		return true
	}
	if !client {
		// IdTCPServer1Execute direct handlers (masterpaskalform.pas:2470-2582).
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
	e.addIncoming(sl, line)
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
				e.ptcAdminMsg(line)
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
				e.PTCSendLine(sl, e.ProtocolLine(31)+n.CFG.DataStr())
			case cmd == "MNFILE":
				e.processMNFile(line)
			case cmd == "SETCFGDATA":
				e.processCFGData(line)
			case cmd == "GETHEADUPDATE":
				e.sendUpdateHeaders(sl, line)
			case cmd == "HEADUPDATE":
				e.headUpdate(line)
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

func (e *Engine) sendFile(sl int, label string, get func() ([]byte, error)) {
	e.peers.mu.Lock()
	s := e.peers.slots[sl]
	e.peers.mu.Unlock()
	if s == nil || s.conn == nil {
		return
	}
	raw, err := get()
	if err != nil {
		raw = nil // Pascal sends an empty stream when the load failed
	}
	if err := s.conn.WriteStream(label, raw); err != nil {
		e.CloseSlot(sl)
	}
}

func (e *Engine) sendResumen(sl int) {
	if e.N.UTCTime() < e.lastSendResumen+10 {
		return
	}
	e.lastSendResumen = e.N.UTCTime()
	e.sendFile(sl, "RESUMENFILE", func() ([]byte, error) { return e.N.Headers.Bytes() })
}

func (e *Engine) sendSumary(sl int) {
	if e.N.UTCTime() < e.lastSendSumary+10 {
		return
	}
	e.lastSendSumary = e.N.UTCTime()
	e.sendFile(sl, "SUMARYFILE", func() ([]byte, error) { return e.N.Summary.Bytes() })
}

// sendBlocks mirrors PTC_SendBlocks: first block = parameter 5 + 1.
func (e *Engine) sendBlocks(sl int, line string) {
	if e.N.UTCTime() < e.lastSendBlocks+10 {
		return
	}
	e.lastSendBlocks = e.N.UTCTime()
	first := codec.StrToIntDef(codec.Parameter(line, 5), -1) + 1
	e.sendFile(sl, "BLOCKZIP", func() ([]byte, error) { return e.N.ZipBlocks(first) })
}

func (e *Engine) sendUpdateHeaders(sl int, line string) {
	if e.N.UTCTime() < e.lastSendUpdHeaders+10 {
		return
	}
	e.lastSendUpdHeaders = e.N.UTCTime()
	blk := codec.StrToIntDef(codec.Parameter(line, 5), 0)
	e.PTCSendLine(sl, e.ProtocolLine(19)+" $"+e.N.Headers.LastHeadersString(int(blk)))
}

// processMNFile mirrors PTC_ProcessMNFileIncoming: accepted only when the
// MD5 of the text + CR LF matches the consensus MNs hash.
func (e *Engine) processMNFile(line string) {
	text := codec.ExtractMNsText(line)
	if codec.Copy(crypto.MD5String(text+"\r\n"), 1, 5) == e.GetConsensus(CMNsHash) {
		e.N.MNFile.Save(text)
	}
}

// processCFGData mirrors PTC_CFGData.
func (e *Engine) processCFGData(line string) {
	content := codec.ExtractMNsText(line)
	if codec.Copy(crypto.MD5String(content), 0, 5) == e.GetConsensus(CCFGHash) {
		e.N.CFG.Save(content)
		e.N.CFG.SetDataStr(content)
		e.logf("events", "Noso CFG updated!")
	} else {
		e.logf("events", "Failed CFG: "+codec.Copy(crypto.MD5String(content), 0, 5)+" <> "+e.GetConsensus(CCFGHash))
	}
}

// headUpdate mirrors PTC_HeadUpdate (mpprotocol.pas:1127-1172).
func (e *Engine) headUpdate(line string) {
	n := e.N
	if n.Headers.Hash() == e.GetConsensus(CHeaders) {
		return
	}
	content := codec.ExtractMNsText(line)
	for i := int64(0); ; i++ {
		h := codec.Parameter(content, i)
		if h == "" {
			break
		}
		h = strings.ReplaceAll(h, ":", " ")
		num := codec.StrToIntDef(codec.Parameter(h, 0), 0)
		if num == int64(n.Headers.LastBlock())+1 {
			n.Headers.Add(num, codec.Parameter(h, 1), codec.Parameter(h, 2))
		}
	}
	n.Headers.SetHash()
	if codec.Copy(n.Headers.Hash(), 0, 5) != e.GetConsensus(CHeaders) {
		e.forceCompleteHeadersDownload = true
		e.logf("console", "Update headers failed")
	} else {
		e.logf("console", "Headers Updated!")
		e.forceCompleteHeadersDownload = false
	}
}

// ptcAdminMsg mirrors PTC_AdminMSG for directives that change the CFG. The
// signature is checked against the developer key; update/restart
// directives are not executed (intentionally skipped, see port-status).
func (e *Engine) ptcAdminMsg(line string) {
	n := e.N
	msgTime, msg, sig, hash := codec.Parameter(line, 5), codec.Parameter(line, 6), codec.Parameter(line, 7), codec.Parameter(line, 8)
	if strings.Contains(e.adminSeen, hash) {
		return
	}
	msg = strings.ReplaceAll(msg, "_", " ")
	if !crypto.VerifySignedString(msgTime+msg, sig, consensus.AdminPubKey) {
		e.logf("events", "Directive wrong sign")
		return
	}
	if crypto.MD5String(msgTime+msg+sig) != hash {
		e.logf("events", "Directive wrong hash")
		return
	}
	e.adminSeen += hash
	cmd, param := strings.ToUpper(codec.Parameter(msg, 0)), codec.Parameter(msg, 1)
	switch cmd {
	case "SETMODE":
		_ = n.CFG.SetData(param, 0)
	case "ADDNODE":
		_ = n.CFG.Add(param, 1)
		e.SetNodesArray(n.CFG.Param(1))
	case "DELNODE":
		_ = n.CFG.Remove(param, 1)
		e.SetNodesArray(n.CFG.Param(1))
	case "ADDNTP":
		_ = n.CFG.Add(param, 2)
	case "DELNTP":
		_ = n.CFG.Remove(param, 2)
	case "ADDLOCKED":
		_ = n.CFG.Add(param, 5)
	case "DELLOCKED":
		_ = n.CFG.Remove(param, 5)
	case "ADDNOSOPAY":
		_ = n.CFG.Add(param, 6)
	case "DELNOSOPAY":
		_ = n.CFG.Remove(param, 6)
	case "CLEARCFG":
		n.CFG.Clear(param)
	case "RESTORECFG":
		n.CFG.Restore()
	}
	e.OutgoingAdd(line)
}
