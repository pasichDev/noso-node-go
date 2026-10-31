package network

import (
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// ReadClientsCheck mirrors LeerLineasDeClientes (mpred.pas:437-454): a slot
// that has not pinged for 15 seconds is closed.
func (e *Engine) ReadClientsCheck() {
	now := e.N.UTCTime()
	for i := 1; i <= MaxConnections; i++ {
		if !e.IsSlotConnected(i) {
			continue
		}
		p := e.peers.get(i)
		if now > codec.StrToInt64Def(p.LastPing, 0)+15 && !p.IsBusy && !e.rebuildingSumary {
			e.logf("events", "Conection closed: Time Out Auth -> "+p.IP)
			e.CloseSlot(i)
		}
		if p.IsBusy {
			e.setLastPing(i, e.N.UTCTimeStr())
		}
	}
}

// VerifyConnectionStatus mirrors mpred.pas:457-554 (states 0..3).
func (e *Engine) VerifyConnectionStatus() {
	n := e.N
	conns := e.TotalConnections()
	if conns == 0 {
		n.ClearMNsChecks()
		n.ClearMNsList()
		n.ClearReceivedOrderIDs()
		n.SetConStatus(0)
		if e.statusConnected {
			e.statusConnected = false
			e.logf("console", "Disconnected.")
			n.ClearPending()
		}
	}
	if conns > 0 && conns < e.MinPeers && n.ConStatus() == 0 {
		n.SetConStatus(1)
		e.lastPing = n.UTCTime()
		e.logf("console", "Connecting...")
	}
	if n.ConStatus() > 0 && e.lastPing+5 < n.UTCTime() {
		e.lastPing = n.UTCTime()
		e.OutgoingAdd(e.ProtocolLine(3))
	}
	if conns >= e.MinPeers && n.ConStatus() < 2 && !e.statusConnected {
		e.statusConnected = true
		n.SetConStatus(2)
		e.logf("console", "Connected.")
	}
	if e.statusConnected && e.lastSyncWithMainnet+4 < n.UTCTime() {
		e.SyncWithMainnet()
	}
	if n.ConStatus() == 2 && e.statusConnected && codec.IntToStr(n.MyLastBlock()) == e.GetConsensus(CLastBlock) &&
		codec.Copy(n.Summary.Hash(), 0, 5) == e.GetConsensus(CSumHash) &&
		codec.Copy(n.Headers.Hash(), 0, 5) == e.GetConsensus(CHeaders) {
		vs, _ := e.ValidSlotForSeed()
		n.ClearReceivedOrderIDs()
		n.SetConStatus(3)
		e.logf("console", "Updated!")
		if n.Options().AutoServer && !e.ServerActive() {
			e.StartServerChecked()
		}
		if codec.StrToIntDef(e.GetConsensus(3), 0) < int64(n.PendingCount()) {
			n.TruncatePending()
		}
		e.PTCSendLine(vs, e.ProtocolLine(11))
		e.lastTimeMNsRequested = n.UTCTime()
		e.OutgoingAdd(e.ProtocolLine(3))
	}
	if n.ConStatus() == 3 {
		vs, _ := e.ValidSlotForSeed()
		o := n.Options()
		if codec.StrToIntDef(e.GetConsensus(3), 0) > int64(n.PendingCount()) &&
			e.lastTimePendingRequested+5 < n.UTCTime() {
			n.ClearReceivedOrderIDs()
			e.PTCSendLine(vs, e.ProtocolLine(5))
			e.lastTimePendingRequested = n.UTCTime()
		}
		if n.Summary.BalanceIndexed(o.MNFunds) < consensus.GetStackRequired(n.MyLastBlock()) {
			e.lastTimeReportMyMN = consensus.NextBlockTimeStamp(n.UTCTime()) + 5
		}
		if !n.MyMNListed(o.MNIP) && e.ServerActive() && n.UTCTime() > e.lastTimeReportMyMN+5 &&
			n.BlockAge() > 10+e.mnsRandomWait && n.BlockAge() < 495 {
			e.OutgoingAdd(e.ProtocolLine(13))
			e.logf("events", "My Masternode reported")
			e.lastTimeReportMyMN = n.UTCTime()
		}
	}
}

// StartServerChecked mirrors StartServer's preconditions (mpred.pas:187-202).
func (e *Engine) StartServerChecked() error {
	o := e.N.Options()
	if e.N.Wallet.IndexOf(o.MNSign) < 0 {
		e.logf("console", "Sign address not valid")
		return errSign
	}
	if e.N.ConStatus() < 3 {
		e.logf("console", "Wallet not updated")
		return errNotUpdated
	}
	return e.StartServer(int(codec.StrToIntDef(o.MNPort, 8080)))
}

type netError string

func (e netError) Error() string { return string(e) }

const (
	errSign       = netError("sign address not valid")
	errNotUpdated = netError("wallet not updated")
)

// SyncWithMainnet mirrors mpred.pas:588-791: it requests whatever file is
// out of line with the consensus, one throttled request per kind.
func (e *Engine) SyncWithMainnet() {
	n := e.N
	if n.Building() > 0 || e.GetConsensus(0) == "" {
		return
	}
	age := n.BlockAge()
	if age < 10 || age > 595 {
		return
	}
	now := n.UTCTime()
	consLB := codec.StrToIntDef(e.GetConsensus(CLastBlock), -1)
	// FIX(M-10, H-04): a vote never deletes a block. Being ahead of the
	// seeds is not an error (they will fetch our blocks), and a different tip
	// is settled by the chain rules (node.AcceptBlocks: heaviest valid
	// branch), not by counting seeds.
	if consLB >= 0 && myLast0(n) >= consLB && n.TipHashAt(consLB) != e.GetConsensus(CLBHash) &&
		e.GetConsensus(CLBHash) != "" && n.TipHashAt(consLB) != "" {
		n.ProbeFork()
	}
	nlbv := codec.StrToIntDef(e.GetConsensus(CLastBlock), 0)
	myLast := n.MyLastBlock()

	if e.GetConsensus(CCFGHash) != codec.Copy(n.CFG.Hash(), 0, 5) && n.CFG.LastRequest+5 < now &&
		e.GetConsensus(CCFGHash) != "" {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.request(s, 30, "CFG")
			n.CFG.LastRequest = now
			e.logf("console", "Noso CFG file requested")
		}
	}
	if e.GetConsensus(CMNsHash) != codec.Copy(n.MNFile.Hash(), 1, 5) && e.lastTimeMNHashRequested+5 < now &&
		e.GetConsensus(CMNsHash) != "" {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.request(s, 16, "MNFILE")
			e.lastTimeMNHashRequested = now
			e.logf("console", "Mns File requested to "+e.peers.get(s).IP)
		}
	}
	// headers
	if codec.Copy(n.Headers.Hash(), 0, 5) != e.GetConsensus(CHeaders) {
		// FIX(H-05): a headers mismatch alone no longer wipes the pool and
		// the masternode tables (mpred.pas:639-641).
		if e.lastTimeRequestResumen+10 < now && !e.downloadHeaders {
			if s, ok := e.ValidSlotForSeed(); ok {
				if nlbv-myLast >= 144 || e.forceCompleteHeadersDownload {
					e.request(s, 7, "RESUMEN")
				} else {
					e.request(s, 18, "HEADUPD")
				}
				e.lastTimeRequestResumen = now
			}
		}
	}
	// blocks
	if codec.Copy(n.Headers.Hash(), 0, 5) == e.GetConsensus(CHeaders) && myLast < nlbv {
		n.ClearPending()
		n.ClearMNsChecks()
		n.ClearMNsList()
		if e.lastTimeRequestBlock+5 < now && !e.downloadBlocks {
			if s, ok := e.ValidSlotForSeed(); ok {
				e.requestBlocks(s)
				e.lastTimeRequestBlock = now
			}
		}
	}
	// a suspected fork: ask for blocks from before our tip
	if n.ForkProbe() && e.lastTimeRequestBlock+5 < now && !e.downloadBlocks {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.requestBlocks(s)
			e.lastTimeRequestBlock = now
		}
	}
	// summary
	if codec.Copy(n.Headers.Hash(), 0, 5) == e.GetConsensus(CHeaders) && myLast == nlbv &&
		codec.Copy(n.Summary.Hash(), 0, 5) != e.GetConsensus(CSumHash) {
		// FIX(C-03): the summary is derived from the blocks we hold and
		// checked while they are applied; it is never downloaded on a vote.
		e.rebuildingSumary = true
		_ = n.CompleteSummary()
		e.rebuildingSumary = false
	}
	// GVTs
	if e.GetConsensus(CGVTsHash) != codec.Copy(n.GVTs.Hash(), 0, 5) && e.lastTimeGVTsRequest+5 < now &&
		e.GetConsensus(CGVTsHash) != "" && !e.downloadGVTs {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.request(s, 20, "GVTS")
			e.lastTimeGVTsRequest = now
		}
	}
	// PSOs
	if e.GetConsensus(20) != codec.Copy(n.PSOs.FileHash(), 0, 5) && e.lastTimePSOsRequest+5 < now &&
		e.GetConsensus(20) != "" && !e.downloadPSOs {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.request(s, 32, "PSOS")
			e.lastTimePSOsRequest = now
		}
	}
	// reported masternodes
	if codec.StrToIntDef(e.GetConsensus(9), 0) > int64(n.MNsListLen()) && e.lastTimeMNsRequested+15 < now &&
		n.WaitingMNsLen() == 0 && age > 30 && n.IsAllSynced() == 0 {
		if s, ok := e.ValidSlotForSeed(); ok {
			n.ClearReceivedMNs()
			n.ClearMNIPProcessed()
			e.PTCSendLine(s, e.ProtocolLine(11))
			e.lastTimeMNsRequested = now
		}
	}
	// masternode verifications
	if codec.StrToIntDef(e.GetConsensus(14), 0) > int64(n.ChecksCount()) && e.lastTimeChecksRequested+5 < now &&
		n.IsAllSynced() == 0 {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.PTCSendLine(s, e.ProtocolLine(15))
			e.lastTimeChecksRequested = now
		}
	}
	// blockchain status issues
	sumPrefix := codec.Copy(n.Summary.Hash(), 0, 5)
	switch {
	case codec.Copy(n.Headers.Hash(), 0, 5) == e.GetConsensus(CHeaders) && myLast == nlbv &&
		sumPrefix != e.GetConsensus(CSumHash) && n.Summary.LastOp() == myLast && e.lastTimeRequestSumary+5 < now:
		n.RebuildOnceFor(myLast) // replay once; a vote cannot replace our state
	case myLast == nlbv && (codec.Copy(n.Headers.Hash(), 0, 5) != e.GetConsensus(CHeaders) ||
		n.MyLastBlockHash() != e.GetConsensus(CLBHash)):
		n.ProbeFork() // FIX(M-10): look at their branch instead of undoing ours
	case codec.Copy(n.Headers.Hash(), 0, 5) != e.GetConsensus(CHeaders) && nlbv == myLast &&
		n.MyLastBlockHash() == e.GetConsensus(CLBHash) && sumPrefix == e.GetConsensus(CSumHash) && !e.downloadHeaders:
		if s, ok := e.ValidSlotForSeed(); ok {
			n.ClearPending()
			e.request(s, 7, "RESUMEN")
			e.lastTimeRequestResumen = now
		}
	}
	if n.IsAllSynced() == 0 {
		e.lastSyncWithMainnet = now
	}
}

var _ = storage.FundsAddress
var _ = strings.TrimSpace

func myLast0(n interface{ MyLastBlock() int64 }) int64 { return n.MyLastBlock() }

// requestBlocks asks a peer for blocks after n.BlocksRequestFrom(): our tip,
// or earlier when a fork is suspected.
func (e *Engine) requestBlocks(slot int) {
	line := e.ProtocolLine(8)
	if i := strings.LastIndex(line, " "); i >= 0 {
		line = line[:i+1] + codec.IntToStr(e.N.BlocksRequestFrom())
	}
	e.expectReply(slot, "BLOCKS")
	e.PTCSendLine(slot, line)
}
