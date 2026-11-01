package network

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// Block propagation. A node learns where a peer's chain stands from the PING
// it sends on every new block and every few seconds: block number and tip
// hash. When a peer is ahead of us, or holds another tip than the block we
// have at that height, we ask it for blocks. Nothing here counts votes. The
// answer is handed to node.StageBlocks, which accepts only blocks sealed by a
// proposer and valid against the state, and settles forks by the chain weight.
// A claim is only a hint where to ask. It never changes the node's status and
// never stops a proposer building: the node counts a peer as ahead only after
// that connection delivered blocks that checked out, and only up to the height
// the chain clock allows. Peers are asked in turn, not by the highest claim; a
// peer that answers with nothing, or with blocks that do not continue the
// chain, is held back for longer each time. A false claim costs one request,
// never a connection.

// pullState is what the puller remembers about one connection.
type pullState struct {
	key     string // peer tip | our tip at the last request
	keyAt   int64
	peerTip string // tip the last request was about
	probed  bool   // already retried once from before our tip
	strikes int    // invalid blocks received on this connection

	delivered  int    // valid blocks this connection has delivered
	faults     int    // empty or wrong-parent answers since the last delivery
	holdUntil  int64  // not asked again before this time
	askSeq     uint64 // when it was last asked, in turns (rotation)
	askedAhead bool   // the last request followed a claim above our tip
}

// holdFor is how long a connection with n faults is not asked again: 10
// seconds for the first, doubled for each further one, at most 5 minutes.
func holdFor(n int) int64 {
	if n < 1 {
		return 0
	}
	if n > 6 {
		n = 6
	}
	return int64(5 << uint(n)) // 10, 20, 40, 80, 160, 320
}

// fault records an answer that gave nothing and holds the peer back.
func (st *pullState) fault(now int64) {
	st.faults++
	st.holdUntil = now + holdFor(st.faults)
}

// claimBound is the highest block number the chain can have reached by now:
// at most one block per block period since the genesis time. A claim above it
// is a lie and is ignored. (It is deliberately not relative to our own tip: a
// node that sat on the short side of a partition has a recent tip and still
// has to believe the longer chain.)
func (e *Engine) claimBound() int64 {
	gap := e.N.UTCTime() - consensus.GenesysTimeStamp
	if gap < 0 {
		gap = 0
	}
	return gap/consensus.SecondsPerBlock + 2
}

// claimCounts reports whether the claim pl of the connection in slot sl may
// hold the node's status back ("2, behind"): it is within claimBound and the
// connection has not been caught giving nothing since it last delivered. The
// status is a hint for the user and for sending orders; it never gates block
// building (see Engine.buildGate).
func (e *Engine) claimCounts(sl int, pl int64) bool {
	if pl > e.claimBound() {
		return false
	}
	s := e.slotObj(sl)
	if s == nil {
		return false
	}
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	return e.pullStateOf(s).faults == 0
}

// pullRetry is how long the same question (same peer tip, same own tip) is
// not asked again.
const pullRetry = 10

// pullTimeout is how long one request may stay unanswered.
const pullTimeout = 10

// maxStrikes invalid answers close a connection.
const maxStrikes = 3

// blockZipBudget bounds the uncompressed size of one block archive. FIX
// (re2 consensus 8): 101 full blocks are about 138 MB, and the receiver
// refuses an archive over 64 MiB, so a chain of full blocks could never be
// fetched. An archive now carries as many consecutive blocks as fit; the
// requester asks again from where the answer ended.
const blockZipBudget = 32 << 20

func (e *Engine) pullStateOf(s *slot) *pullState {
	st := e.peerSync[s]
	if st == nil {
		st = &pullState{}
		e.peerSync[s] = st
	}
	return st
}

// syncBlocks asks one peer for blocks when it is ahead of us or on another
// branch. At most one request is in flight. The peers that qualify take turns
// (the one asked longest ago goes first), so no claim, however high, owns the
// pull; a peer that was caught giving nothing is held back for a while.
func (e *Engine) syncBlocks() {
	n := e.N
	if n.Building() > 0 {
		return
	}
	now := e.now()
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	if e.pullSlot != nil {
		if now < e.pullAt+pullTimeout {
			return
		}
		// no answer at all to a claim above our tip counts as an empty one
		if st := e.peerSync[e.pullSlot]; st != nil && st.askedAhead {
			st.fault(now)
		}
	}
	e.pullSlot = nil
	for s := range e.peerSync { // forget closed connections
		if e.slotNumber(s) == 0 {
			delete(e.peerSync, s)
		}
	}
	myLast, myTip := n.MyLastBlock(), n.MyLastBlockHash()
	bound := e.claimBound()
	best, bestKind := 0, 0
	var bestSt *pullState
	for i := 1; i <= MaxConnections; i++ {
		if !e.IsSlotConnected(i) {
			continue
		}
		p, s := e.peers.get(i), e.slotObj(i)
		if !p.Autentic || s == nil {
			continue
		}
		pl, ph := codec.StrToInt64Def(p.LastBlock, -1), p.LastBlockHash
		if pl < 0 || ph == "" || pl > bound {
			continue
		}
		kind := 0
		switch {
		case pl > myLast:
			kind = 1
		case !e.sameBranchAtLocked(i, pl, ph, myTip):
			kind = 2
		}
		if kind == 0 {
			continue
		}
		st := e.pullStateOf(s)
		if now < st.holdUntil {
			continue
		}
		if st.key == ph+"|"+myTip && now < st.keyAt+pullRetry {
			continue
		}
		if best == 0 || st.askSeq < bestSt.askSeq ||
			(st.askSeq == bestSt.askSeq && (st.delivered > bestSt.delivered ||
				(st.delivered == bestSt.delivered && kind < bestKind))) {
			best, bestKind, bestSt = i, kind, st
		}
	}
	if best == 0 {
		return
	}
	s := e.slotObj(best)
	if s == nil {
		return
	}
	st := bestSt
	pl := codec.StrToInt64Def(e.peers.get(best).LastBlock, -1)
	e.pullSeq++
	st.askSeq, st.askedAhead = e.pullSeq, pl > myLast
	st.key, st.keyAt, st.peerTip = e.peers.get(best).LastBlockHash+"|"+myTip, now, e.peers.get(best).LastBlockHash
	if bestKind == 2 {
		n.ProbeFork()
	}
	e.pullSlot, e.pullAt = s, now
	e.requestBlocks(best)
}

// rejectKey names a tip that one connection showed and that lost against ours.
// It is bound to the connection: a peer that claims a tip and answers with
// nothing must not make us ignore the same tip on the connections that hold it.
func (e *Engine) rejectKey(sl int, hash, myTip string) string {
	return e.peerKey(sl) + "|" + hash + "|" + myTip
}

func (e *Engine) sameBranchAtLocked(sl int, num int64, hash, myTip string) bool {
	if num > e.N.MyLastBlock() {
		return true
	}
	if e.N.TipHashAt(num) == hash {
		return true
	}
	return e.rejected[e.rejectKey(sl, hash, myTip)]
}

// slotNumber returns the number of a slot object, 0 when it is gone.
func (e *Engine) slotNumber(s *slot) int {
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	for i := 1; i <= MaxConnections; i++ {
		if e.peers.slots[i] == s {
			return i
		}
	}
	return 0
}

// blocksReceived handles the archive a peer sent for our request. It returns
// false only for a peer that keeps sending invalid blocks. A peer on another
// branch or a branch that is not heavier than ours are normal events and never cost the connection.
func (e *Engine) blocksReceived(sl int, data []byte) bool {
	n := e.N
	s := e.slotObj(sl)
	stored, err := n.StageBlocks(data)
	e.syncMu.Lock()
	var st *pullState
	if s != nil {
		st = e.pullStateOf(s)
	}
	if e.pullSlot == s {
		e.pullSlot = nil
	}
	peerTip := ""
	if st != nil {
		peerTip = st.peerTip
	}
	switch {
	case stored > 0:
		if st != nil {
			st.probed, st.strikes, st.keyAt = false, 0, 0
			st.delivered += stored
			st.faults, st.holdUntil = 0, 0
		}
	case err == nil:
		// Nothing new. If a branch is being staged (it is not heavier yet) the
		// next window continues it from its tip, so ask the same peer again
		// at once; only when the peer has nothing beyond that is the pair of
		// tips given up on.
		from := n.BlocksRequestFrom()
		peerLast := codec.StrToInt64Def(e.peers.get(sl).LastBlock, -1)
		if st != nil && !n.ForkProbe() && from != n.MyLastBlock() && from < peerLast {
			st.keyAt = 0
		} else {
			if peerTip != "" {
				e.markRejected(e.rejectKey(sl, peerTip, n.MyLastBlockHash()))
			}
			if st != nil && st.askedAhead {
				st.fault(e.now()) // it claimed to be ahead and gave us nothing
			}
		}
	case errors.Is(err, node.ErrForkParent):
		// the peer is on another branch: ask once more from before our tip
		if st != nil && !st.probed {
			st.probed, st.keyAt = true, 0
		} else if st != nil {
			st.fault(e.now()) // blocks that still do not continue our chain
		}
	}
	e.syncMu.Unlock()
	if stored > 0 {
		e.logf("events", "blocks stored: "+codec.IntToStr(int64(stored))+", last "+codec.IntToStr(n.MyLastBlock()))
		e.OutgoingAdd(e.ProtocolLine(3)) // announce the new tip to every peer
	}
	if err == nil || errors.Is(err, node.ErrForkParent) || errors.Is(err, node.ErrCorrupt) || errors.Is(err, node.ErrNoProposers) {
		return true
	}
	e.logf("events", "blocks refused: "+err.Error())
	if st == nil {
		return true
	}
	e.syncMu.Lock()
	st.strikes++
	if errors.Is(err, node.ErrUnsealed) {
		st.strikes = maxStrikes // an unsealed block is not a fork: no second chance
		st.fault(e.now())
	}
	over := st.strikes >= maxStrikes
	e.syncMu.Unlock()
	if over {
		e.UpdateBotData(e.peers.get(sl).IP)
		return false
	}
	return true
}

func (e *Engine) markRejected(k string) {
	if len(e.rejected) > 1024 {
		e.rejected = map[string]bool{}
	}
	e.rejected[k] = true
}

// zipBlocksFrom archives the blocks first, first+1, ... (at most 101 and at
// most blockZipBudget bytes, consecutive, never a gap).
func (e *Engine) zipBlocksFrom(first int64) ([]byte, error) {
	n := e.N
	if first < 0 {
		first = 0
	}
	last := first + 100
	if last > n.MyLastBlock() {
		last = n.MyLastBlock()
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	total := 0
	for i := first; i <= last; i++ {
		raw, err := os.ReadFile(n.Lay.BlockFile(i))
		if err != nil {
			break
		}
		if total > 0 && total+len(raw) > blockZipBudget {
			break
		}
		w, err := zw.Create(codec.IntToStr(i) + ".blk")
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(raw); err != nil {
			return nil, err
		}
		total += len(raw)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
