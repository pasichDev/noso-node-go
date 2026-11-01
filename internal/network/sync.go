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
	now := e.now()
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
			e.setLastPing(i, e.nowStr())
		}
	}
}

// requiredPeers is how many connections the node wants before it counts as
// connected: MinPeers, but never more than the number of other nodes it is
// configured to talk to. A node with nobody configured is a standalone chain
// and needs none.
func (e *Engine) requiredPeers() int {
	others := 0
	for _, h := range e.nodesList() {
		if !e.isSelf(h.ip, h.port) {
			others++
		}
	}
	if others < e.MinPeers {
		return others
	}
	return e.MinPeers
}

// isSelf reports whether ip:port names this node's own listener.
func (e *Engine) isSelf(ip, port string) bool {
	e.mu.Lock()
	on, sp := e.serverOn, e.serverPort
	e.mu.Unlock()
	if !on || int64(sp) != codec.StrToIntDef(port, 8080) {
		return false
	}
	return isLoopback(ip) || ip == e.N.Options().MNIP
}

// heardEnough reports whether at least `need` authenticated peers are
// connected, whatever they claim. A proposer builds on its own verified state
// once it has heard from its peers; their claims about their height do not
// gate building (final review F-2).
func (e *Engine) heardEnough(need int) bool {
	heard := 0
	for i := 1; i <= MaxConnections; i++ {
		if e.IsSlotConnected(i) && e.peers.get(i).Autentic {
			heard++
		}
	}
	return heard >= need
}

// caughtUp reports whether no authenticated peer is ahead of us or on a tip
// we have not weighed against ours. It is derived from what the peers say in
// their PING, never from a vote: the blocks themselves are checked when they
// are fetched. A claim holds the status back only while it is plausible and
// its sender has not been caught answering with nothing (claimCounts).
func (e *Engine) caughtUp(need int) bool {
	n := e.N
	myLast := n.MyLastBlock()
	authentic := 0
	for i := 1; i <= MaxConnections; i++ {
		if !e.IsSlotConnected(i) {
			continue
		}
		p := e.peers.get(i)
		if !p.Autentic {
			continue
		}
		authentic++
		pl := codec.StrToInt64Def(p.LastBlock, -1)
		// A claim is a hint, not a fact: it holds the node back only when that
		// connection has already delivered valid blocks and the height is one
		// the chain clock allows (see claimCounts).
		if pl > myLast && e.claimCounts(i, pl) {
			return false
		}
		if pl >= 0 && pl <= myLast && !e.sameBranchAt(i, pl, p.LastBlockHash) && e.claimCounts(i, pl) {
			return false
		}
	}
	return authentic >= need
}

// sameBranchAt reports whether a peer's tip (number, hash) is a block of our
// chain or has already been weighed against our tip and lost.
func (e *Engine) sameBranchAt(sl int, num int64, hash string) bool {
	if hash == "" || num > e.N.MyLastBlock() {
		return true
	}
	if e.N.TipHashAt(num) == hash {
		return true
	}
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	return e.rejected[e.rejectKey(sl, hash, e.N.MyLastBlockHash())]
}

// VerifyConnectionStatus sets the node state: 0 not connected, 1 connecting,
// 2 connected but behind (or not yet heard from enough peers), 3 up to date.
// FIX(C1, H-5): the original reached state 3 only when more than half of the
// seeds voted for exactly our blocks, so a block built by one proposer could
// never be adopted by anyone and the builder was held back by its own block.
func (e *Engine) VerifyConnectionStatus() {
	n := e.N
	conns := e.TotalConnections()
	required := e.requiredPeers()
	if conns == 0 {
		n.ClearMNsChecks()
		n.ClearMNsList()
		n.ClearReceivedOrderIDs()
		if e.statusConnected {
			e.statusConnected = false
			e.logf("console", "Disconnected.")
			n.ClearPending()
		}
	}
	e.mu.Lock()
	e.canBuild = conns >= required && e.heardEnough(required)
	e.mu.Unlock()
	prev := n.ConStatus()
	status := 3
	switch {
	case conns == 0 && required > 0:
		status = 0
	case conns < required:
		status = 1
	case !e.caughtUp(required):
		status = 2
	}
	if status != prev {
		n.SetConStatus(status)
		switch {
		case status == 1:
			e.logf("console", "Connecting...")
		case status == 2 && prev < 2:
			e.statusConnected = true
			e.logf("console", "Connected.")
		case status == 3:
			e.statusConnected = true
			n.ClearReceivedOrderIDs()
			e.logf("console", "Updated!")
			if s, ok := e.anyPeerSlot(); ok {
				e.PTCSendLine(s, e.ProtocolLine(5))
				e.PTCSendLine(s, e.ProtocolLine(11))
			}
			e.lastTimeMNsRequested = e.now()
			e.OutgoingAdd(e.ProtocolLine(3))
		}
	}
	if n.ConStatus() > 0 && e.lastPing+5 < e.now() {
		e.lastPing = e.now()
		e.OutgoingAdd(e.ProtocolLine(3))
	}
	e.syncBlocks()
	if e.lastSyncWithMainnet+4 < e.now() {
		e.SyncWithMainnet()
	}
	if n.ConStatus() == 3 {
		o := n.Options()
		if vs, ok := e.peerWithMorePending(); ok && e.lastTimePendingRequested+5 < e.now() {
			n.ClearReceivedOrderIDs()
			e.PTCSendLine(vs, e.ProtocolLine(5))
			e.lastTimePendingRequested = e.now()
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

// anyPeerSlot returns a connected slot that has sent a PING, rotating.
func (e *Engine) anyPeerSlot() (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for c := 0; c < MaxConnections; c++ {
		e.slotCount++
		if e.slotCount > MaxConnections {
			e.slotCount = 1
		}
		if e.IsSlotConnected(e.slotCount) && e.peers.get(e.slotCount).Autentic {
			return e.slotCount, true
		}
	}
	return 0, false
}

// peerWithMorePending finds a peer that reports more pending orders than we
// hold (replaces the seed vote on the pending count).
func (e *Engine) peerWithMorePending() (int, bool) {
	mine := e.N.PendingCount()
	for i := 1; i <= MaxConnections; i++ {
		if e.IsSlotConnected(i) && e.peers.get(i).Autentic && e.peers.get(i).Pending > mine {
			return i, true
		}
	}
	return 0, false
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

// SyncWithMainnet keeps the small shared tables in line with what the seeds
// report: the signed configuration, the masternode file and list and the
// verification records. It touches neither blocks nor state files: blocks come
// from syncBlocks (checked one by one), and the summary, headers, GVT and PSO
// files are derived from the blocks. FIX(M-3): a seed vote used to replace the
// GVT and PSO files and to decide which blocks were wanted.
func (e *Engine) SyncWithMainnet() {
	n := e.N
	if n.Building() > 0 || e.GetConsensus(0) == "" {
		return
	}
	age := n.BlockAge()
	if age < 10 || age > 595 {
		return
	}
	now := e.now()
	if e.GetConsensus(CCFGHash) != codec.Copy(n.CFG.Hash(), 0, 5) && n.CFG.LastRequest+5 < n.UTCTime() &&
		e.GetConsensus(CCFGHash) != "" {
		if s, ok := e.ValidSlotForSeed(); ok {
			e.request(s, 30, "CFG")
			n.CFG.LastRequest = n.UTCTime()
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
	if n.IsAllSynced() == 0 {
		e.lastSyncWithMainnet = now
	}
}

var _ = storage.FundsAddress
var _ = strings.TrimSpace

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
