package network

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// Block propagation. A node learns where a peer's chain stands from the PING
// it sends on every new block and every few seconds: block number and tip
// hash. When a peer is ahead of us, or holds another tip than the block we
// have at that height, we ask it for blocks. Nothing here counts votes. The
// answer is handed to node.StageBlocks, which accepts only blocks sealed by a
// proposer and valid against the state, and settles forks by the chain weight.
// A false claim costs one request, never a connection.

// pullState is what the puller remembers about one connection.
type pullState struct {
	key     string // peer tip | our tip at the last request
	keyAt   int64
	peerTip string // tip the last request was about
	probed  bool   // already retried once from before our tip
	strikes int    // invalid blocks received on this connection
}

// pullRetry is how long the same question (same peer tip, same own tip) is
// not asked again.
const pullRetry = 10

// pullTimeout is how long one request may stay unanswered.
const pullTimeout = 30

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
// branch. At most one request is in flight.
func (e *Engine) syncBlocks() {
	n := e.N
	if n.Building() > 0 {
		return
	}
	now := e.now()
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	if e.pullSlot != nil && now < e.pullAt+pullTimeout {
		return
	}
	e.pullSlot = nil
	for s := range e.peerSync { // forget closed connections
		if e.slotNumber(s) == 0 {
			delete(e.peerSync, s)
		}
	}
	myLast, myTip := n.MyLastBlock(), n.MyLastBlockHash()
	best, bestKind, bestLast := 0, 0, int64(-1)
	for i := 1; i <= MaxConnections; i++ {
		if !e.IsSlotConnected(i) {
			continue
		}
		p, s := e.peers.get(i), e.slotObj(i)
		if !p.Autentic || s == nil {
			continue
		}
		pl, ph := codec.StrToInt64Def(p.LastBlock, -1), p.LastBlockHash
		if pl < 0 || ph == "" {
			continue
		}
		kind := 0
		switch {
		case pl > myLast:
			kind = 1
		case !e.sameBranchAtLocked(pl, ph, myTip):
			kind = 2
		}
		if kind == 0 {
			continue
		}
		st := e.pullStateOf(s)
		if st.key == ph+"|"+myTip && now < st.keyAt+pullRetry {
			continue
		}
		if best == 0 || kind < bestKind || (kind == bestKind && pl > bestLast) {
			best, bestKind, bestLast = i, kind, pl
		}
	}
	if best == 0 {
		return
	}
	s := e.slotObj(best)
	if s == nil {
		return
	}
	st := e.pullStateOf(s)
	st.key, st.keyAt, st.peerTip = e.peers.get(best).LastBlockHash+"|"+myTip, now, e.peers.get(best).LastBlockHash
	if bestKind == 2 {
		n.ProbeFork()
	}
	e.pullSlot, e.pullAt = s, now
	e.requestBlocks(best)
}

func (e *Engine) sameBranchAtLocked(num int64, hash, myTip string) bool {
	if num > e.N.MyLastBlock() {
		return true
	}
	if e.N.TipHashAt(num) == hash {
		return true
	}
	return e.rejected[hash+"|"+myTip]
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
// branch, a branch below our finality horizon, or a branch that is not
// heavier than ours are normal events and never cost the connection.
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
		}
	case err == nil:
		// nothing new, or a branch that is not preferred: do not ask again
		// for this pair of tips.
		if peerTip != "" {
			e.markRejected(peerTip + "|" + n.MyLastBlockHash())
		}
	case errors.Is(err, node.ErrForkParent):
		// the peer is on another branch: ask once more from before our tip
		if st != nil && !st.probed {
			st.probed, st.keyAt = true, 0
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
	if softBlockError(err) || st == nil {
		return true
	}
	e.syncMu.Lock()
	st.strikes++
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

// softBlockError recognises a refusal that comes from the chain position, not
// from the peer: a branch forking below the finality horizon.
func softBlockError(err error) bool {
	m := err.Error()
	return strings.Contains(m, "below the finality horizon") || strings.Contains(m, "no undo data")
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
