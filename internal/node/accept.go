package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// ErrForkParent is returned when received blocks do not continue our chain;
// the caller should ask for blocks from further back (BlocksRequestFrom).
var ErrForkParent = errors.New("received blocks do not continue our chain")

// ForkProbe reports that a peer showed us blocks on another branch, so the
// next request should start before our tip.
func (n *Node) ForkProbe() bool {
	n.chainState.mu.Lock()
	defer n.chainState.mu.Unlock()
	return n.chainState.probe
}

// ProbeFork asks the next block request to start before our tip. The sync
// layer calls it when a peer's tip differs from ours at the same height.
func (n *Node) ProbeFork() { n.setProbe(true) }

func (n *Node) setProbe(v bool) {
	n.chainState.mu.Lock()
	n.chainState.probe = v
	n.chainState.mu.Unlock()
}

// BlocksRequestFrom is the "last block we have" number to put in a block
// request: our tip normally. While a branch is staged it is the staged tip
// (the next window continues it); while a fork is suspected it is the probe
// depth before our tip, which doubles each time the answer does not link, so
// a fork of any depth is found (FIX(re2 3b, 10)).
func (n *Node) BlocksRequestFrom() int64 {
	n.chainState.mu.Lock()
	staged, tip, probe, depth := len(n.chainState.staged) > 0, n.chainState.stagedTip, n.chainState.probe, n.chainState.probeDepth
	n.chainState.mu.Unlock()
	if staged {
		return tip
	}
	last := n.MyLastBlock()
	if !probe {
		return last
	}
	if depth < MaxReorgDepth {
		depth = MaxReorgDepth
	}
	from := last - depth
	if from < 0 {
		from = 0
	}
	return from
}

func (n *Node) deepenProbe() {
	n.chainState.mu.Lock()
	n.chainState.probe = true
	if n.chainState.probeDepth < MaxReorgDepth {
		n.chainState.probeDepth = MaxReorgDepth
	} else {
		n.chainState.probeDepth *= 2
	}
	n.chainState.mu.Unlock()
}

func (n *Node) clearStaged() {
	n.chainState.mu.Lock()
	n.chainState.staged, n.chainState.stagedStart, n.chainState.stagedTip = nil, 0, 0
	n.chainState.mu.Unlock()
}

// maxStaged bounds the branch kept in memory while it is compared.
const maxStaged = 20000

type cand struct {
	blk     *storage.Block
	raw     []byte
	hash    string
	score   int64
	sumHash string
	moved   bool
}

// blockScoreAt is the score of our own block num.
func (n *Node) blockScoreAt(num int64) int64 {
	blk, err := n.Blocks.Read(num)
	if err != nil || !blk.V2 {
		return 0
	}
	props := n.Proposers()
	return BlockScore(len(props), indexOfKey(props, blk.SealKey), SlotOf(blk.Header.TimeEnd), SlotOf(n.Blocks.Header(num-1).TimeEnd))
}

// acceptRunLocked is the one place where blocks from outside enter the chain
// (FIX(C-03, M-10)). byNum holds raw block files by number. Blocks identical
// to ours are skipped; the first differing block must continue one of our
// blocks. The seals, links and scores of the run are checked first, before any
// state is touched. A branch is adopted when it extends our tip or beats our
// blocks above the fork (BlockScore, then Preferred); nothing else decides,
// so every node that sees the same blocks ends on the same chain whatever
// its own history (FIX(re2 3): no local finality in the decision). A branch
// that does not beat ours yet is staged so the next windows can complete it.
func (n *Node) acceptRunLocked(byNum map[int64][]byte) (int, error) {
	if n.isCorrupt() {
		return 0, ErrCorrupt
	}
	props := n.Proposers()
	if len(props) == 0 {
		return 0, ErrNoProposers
	}
	k := len(props)
	// A staged branch continues with the next window.
	n.chainState.mu.Lock()
	if len(n.chainState.staged) > 0 {
		lo := int64(-1)
		for x := range byNum {
			if lo < 0 || x < lo {
				lo = x
			}
		}
		if lo == n.chainState.stagedTip+1 && len(n.chainState.staged)+len(byNum) <= maxStaged {
			merged := make(map[int64][]byte, len(n.chainState.staged)+len(byNum))
			for x, v := range n.chainState.staged {
				merged[x] = v
			}
			for x, v := range byNum {
				merged[x] = v
			}
			byNum = merged
		}
	}
	n.chainState.mu.Unlock()

	var nums []int64
	for x := range byNum {
		nums = append(nums, x)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	last := n.MyLastBlock()
	start := int64(-1)
	for _, x := range nums {
		if x <= last && crypto.IDHashBytes(byNum[x]) == crypto.IDHashFile(n.Lay.BlockFile(x)) {
			continue // already ours
		}
		start = x
		break
	}
	if start < 0 {
		n.setProbe(false)
		n.clearStaged()
		return 0, nil
	}
	if start > last+1 || start < 1 {
		return 0, nil // not contiguous with anything we hold
	}
	fork := start - 1 // last block we keep

	// ---- phase 1: seals, links, scores; no state is touched ----
	prev := n.Blocks.Header(fork)
	prevHash := crypto.IDHashFile(n.Lay.BlockFile(fork))
	var pre []cand
	var firstErr error
	for num := start; ; num++ {
		raw, ok := byNum[num]
		if !ok {
			break
		}
		blk, err := storage.DecodeBlock(raw)
		if err == nil && !bytes.Equal(blk.Encode(), raw) {
			err = bad("block %d is not in canonical form", num)
		}
		if err == nil && blk.Header.Number != num {
			err = bad("file %d.blk holds block %d", num, blk.Header.Number)
		}
		if err == nil && blk.Header.LastBlockHash != prevHash {
			err = bad("parent hash %q != %q", blk.Header.LastBlockHash, prevHash)
			if len(pre) == 0 {
				err = errors.Join(ErrForkParent, err)
			}
		}
		var idx int
		if err == nil {
			if !blk.V2 || len(blk.Keys) != len(blk.Orders) {
				err = bad("block has no authentication trailer")
			} else {
				idx, err = n.checkSeal(blk)
			}
		}
		if err != nil {
			firstErr = err
			break
		}
		pre = append(pre, cand{blk: blk, raw: raw, hash: crypto.IDHashBytes(raw),
			score: BlockScore(k, idx, SlotOf(blk.Header.TimeEnd), SlotOf(prev.TimeEnd))})
		prev, prevHash = blk.Header, pre[len(pre)-1].hash
	}
	if len(pre) == 0 {
		n.clearStaged()
		if errors.Is(firstErr, ErrForkParent) {
			n.deepenProbe()
		}
		return 0, firstErr
	}
	n.chainState.mu.Lock()
	n.chainState.probeDepth = 0
	n.chainState.mu.Unlock()

	var ours int64
	var ourTime int64
	var ourTip string
	if start <= last {
		for b := start; b <= last; b++ {
			ours += n.blockScoreAt(b)
		}
		ourTime, ourTip = n.Blocks.Header(last).TimeEnd, n.tipHashAt(last)
		var sum int64
		best := false
		for _, c := range pre {
			sum += c.score
			if Preferred(sum, c.blk.Header.TimeEnd, c.hash, ours, ourTime, ourTip) {
				best = true
				break
			}
		}
		if !best {
			// Not heavier (yet). Keep it if the run may continue.
			if firstErr == nil && len(byNum) < maxStaged {
				n.chainState.mu.Lock()
				n.chainState.staged, n.chainState.stagedStart = byNum, start
				n.chainState.stagedTip = pre[len(pre)-1].blk.Header.Number
				n.chainState.mu.Unlock()
			} else {
				n.clearStaged()
			}
			n.setProbe(false)
			return 0, firstErr
		}
	}

	// ---- phase 2: apply to the state, then commit through the journal ----
	defer n.dropEvalSnapshots()
	if err := n.snapshot("tip"); err != nil {
		return 0, err
	}
	if err := n.beginJournal("tip", last); err != nil {
		return 0, err
	}
	putBack := func() {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot("tip")
		n.endJournal()
	}
	if start <= last {
		var err error
		if n.hasSnapshot(codec.IntToStr(start)) {
			err = n.restoreSnapshot(codec.IntToStr(start))
		} else {
			// No undo data this far back: replay our own blocks up to the fork.
			err = n.rebuildLocked(fork, nil)
		}
		if err != nil {
			putBack()
			return 0, err
		}
	}
	prev = n.Blocks.Header(fork)
	prevHash = crypto.IDHashFile(n.Lay.BlockFile(fork))
	recent := map[string]bool{}
	for _, o := range n.Blocks.Orders(fork) {
		recent[o.TrfrID] = true
	}
	var cands []cand
	for i := range pre {
		c := pre[i]
		sum, moved, err := n.evalBlock(c.blk, prev, prevHash, recent, "c"+codec.IntToStr(c.blk.Header.Number))
		if err != nil {
			firstErr = err
			break
		}
		c.sumHash, c.moved = sum, moved
		cands = append(cands, c)
		prev, prevHash = c.blk.Header, c.hash
		recent = map[string]bool{}
		for _, o := range c.blk.Orders {
			recent[o.TrfrID] = true
		}
	}
	if len(cands) == 0 {
		putBack()
		n.clearStaged()
		return 0, firstErr
	}
	if start <= last {
		var weight int64
		for _, c := range cands {
			weight += c.score
		}
		tipc := cands[len(cands)-1]
		if !Preferred(weight, tipc.blk.Header.TimeEnd, tipc.hash, ours, ourTime, ourTip) {
			putBack()
			n.setProbe(false)
			n.clearStaged()
			return 0, firstErr
		}
	}
	blocks := map[int64][]byte{}
	for _, c := range cands {
		blocks[c.blk.Header.Number] = c.raw
	}
	if err := n.commitJournal("c"+codec.IntToStr(start), last, start, blocks); err != nil {
		putBack()
		return 0, err
	}
	if err := n.writeCands(start, last, cands); err != nil {
		// The journal is durable; replay it now, or leave it to the next start.
		n.failedCommit()
		return 0, err
	}
	n.endJournal()
	for _, c := range cands {
		n.promoteSnapshot(c.blk.Header.Number)
	}
	tip := start + int64(len(cands)) - 1
	n.Summary.SetLastOp(tip)
	n.Summary.SetHash()
	n.Headers.SetHash()
	n.noteTip(tip)
	n.pruneSnapshots(tip)
	n.setProbe(false)
	n.clearStaged()
	// A new period begins: reports and lists of the old one are void.
	n.ClearMNsChecks()
	n.ClearMNsList()
	n.ClearReceivedMNs()
	if start <= last {
		n.logf("console", "Adopted a heavier branch from block "+codec.IntToStr(start))
	}
	return len(cands), firstErr
}

// writeCands replaces our blocks above the fork with the candidates.
func (n *Node) writeCands(start, last int64, cands []cand) error {
	for b := last; b >= start; b-- {
		n.Blocks.Delete(b)
	}
	if start <= last && n.DB != nil {
		if err := n.DB.RollbackTo(int32(start - 1)); err != nil {
			return err
		}
	}
	for n.Headers.Height() >= int(start) && n.Headers.RemoveLast() {
	}
	for i, c := range cands {
		num := start + int64(i)
		if err := n.Blocks.Write(c.blk); err != nil {
			return err
		}
		n.SetMyLastBlock(num)
		if !n.Headers.Add(num, c.hash, c.sumHash) {
			return errHeaderWrite
		}
	}
	n.UpdateMyData()
	return nil
}

// failedCommit handles a write failure after the commit point: recover from
// the journal once; if that fails too the node stops until it is restarted.
func (n *Node) failedCommit() {
	if n.chainState.recovering {
		n.markCorrupt()
		return
	}
	n.chainState.recovering = true
	err := n.recoverLocked()
	n.chainState.recovering = false
	if err != nil {
		n.markCorrupt()
	}
}

// promoteSnapshot turns the evaluation snapshot of a block into its undo
// snapshot.
func (n *Node) promoteSnapshot(num int64) {
	_ = removeAll(n.undoDir(codec.IntToStr(num)))
	_ = renameDir(n.undoDir("c"+codec.IntToStr(num)), n.undoDir(codec.IntToStr(num)))
}

// dropEvalSnapshots removes the scratch snapshots of a branch evaluation.
func (n *Node) dropEvalSnapshots() {
	entries, _ := os.ReadDir(filepath.Join(n.Lay.Root, "UNDO"))
	for _, e := range entries {
		if nm := e.Name(); nm == "tip" || (len(nm) > 1 && nm[0] == 'c') {
			_ = os.RemoveAll(filepath.Join(n.Lay.Root, "UNDO", nm))
		}
	}
}

func (n *Node) tipHashAt(num int64) string { return crypto.IDHashFile(n.Lay.BlockFile(num)) }

// evalBlock validates a block against the chain and applies it to the state
// files (not to the block store). On failure the state is put back to the
// moment before this block.
func (n *Node) evalBlock(blk *storage.Block, prev types.BlockHeader, prevHash string, recent map[string]bool, label string) (sum string, moved bool, err error) {
	if err = n.ValidateBlock(blk, prev, prevHash, recent); err != nil {
		return
	}
	if err = n.snapshot(label); err != nil {
		return
	}
	n.Summary.ResetBlockRecords()
	moved, err = n.applyBlockState(blk)
	if err == nil {
		err = n.Summary.UpdateChanges()
	}
	if err != nil {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot(label)
		return "", false, bad("%v", err)
	}
	n.Summary.SetLastOp(blk.Header.Number)
	if err = n.persistDerived(blk.Header.Number, moved); err == nil {
		// FIX(re2 1): the block names the state it produces; a node that is
		// not on that state refuses the block.
		root, _, _ := parseSolution(blk.Header.Solution)
		if root != n.stateRoot() {
			err = bad("state root of block %d differs from the state it produces ", blk.Header.Number)
		}
	}
	if err != nil {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot(label)
		return "", false, err
	}
	return n.Summary.Hash(), moved, nil
}

// AcceptBlocks takes the lock itself (tests and callers outside the
// package).
func (n *Node) AcceptBlocks(byNum map[int64][]byte) (int, error) {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.acceptRunLocked(byNum)
}

// TipHashAt is the identity hash of block num as stored, "" when absent.
func (n *Node) TipHashAt(num int64) string {
	if !storage.Exists(n.Lay.BlockFile(num)) {
		return ""
	}
	return crypto.IDHashFile(n.Lay.BlockFile(num))
}

// RebuildOnceFor rebuilds the summary by replaying the chain, at most once
// per tip, and reports whether it ran. The sync layer uses it instead of
// downloading a summary on a vote: the state is derived from the blocks.
func (n *Node) RebuildOnceFor(tip int64) bool {
	n.chainMu.Lock()
	if n.rebuiltFor == tip+1 {
		n.chainMu.Unlock()
		return false
	}
	n.rebuiltFor = tip + 1
	err := n.rebuildSummaryLocked()
	n.chainMu.Unlock()
	if err != nil {
		n.logf("exceps", "rebuild summary: "+err.Error())
	}
	return true
}
