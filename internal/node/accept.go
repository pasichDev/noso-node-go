package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// ErrForkParent is returned when received blocks do not continue our chain;
// the caller should ask for blocks from further back (BlocksRequestFrom).
var ErrForkParent = errors.New("received blocks do not continue our chain")

// ErrUnsealed is returned for a received block that is not sealed by a listed
// proposer (no trailer, an unlisted key, a bad signature). It is not a block
// of another branch: the network layer strikes a peer that sends one.
var ErrUnsealed = errors.New("block is not sealed by a listed proposer")

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
	if !v {
		n.chainState.probeDepth, n.chainState.probeResume = 0, 0
	}
	n.chainState.mu.Unlock()
}

// BlocksRequestFrom is the "last block we have" number to put in a block
// request: our tip normally. While a branch is staged it is the staged tip
// (the next window continues it); while a fork is suspected it is the probe
// depth before our tip, which doubles each time the answer does not link, so
// a fork of any depth is found (FIX(re2 3b, 10)).
func (n *Node) BlocksRequestFrom() int64 {
	n.chainState.mu.Lock()
	staged, tip, probe, depth, resume := len(n.chainState.staged) > 0, n.chainState.stagedTip, n.chainState.probe, n.chainState.probeDepth, n.chainState.probeResume
	n.chainState.mu.Unlock()
	if staged {
		return tip
	}
	last := n.MyLastBlock()
	if !probe {
		return last
	}
	if resume > 0 && resume <= last {
		return resume // a window of common blocks was read: go on after it
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
	n.chainState.probeResume = 0 // a window that does not link ends the walk forward
	if n.chainState.probeDepth < MaxReorgDepth {
		n.chainState.probeDepth = MaxReorgDepth
	} else {
		n.chainState.probeDepth *= 2
	}
	n.chainState.mu.Unlock()
}

func (n *Node) clearStaged() {
	n.chainState.mu.Lock()
	n.chainState.staged, n.chainState.stagedBytes, n.chainState.stagedTip = nil, 0, 0
	n.chainState.mu.Unlock()
}

// The branch kept in memory while it is compared is bounded in blocks and in
// bytes (a block may be 8 MiB).
var (
	maxStaged             = 20000
	maxStagedBytes  int64 = 256 << 20
	errStagingLimit       = bad("branch longer than the staging limit")
)

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
// blocks above the fork (BlockScore, then Preferred); nothing else decides and
// nothing depends on the node's own history (FIX(re2 3): no local finality in
// the decision). Nodes given the same blocks converge, but a run is judged as
// delivered, so the order of deliveries can leave two nodes on different tips
// until the next pull. A branch
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
	last := n.MyLastBlock()
	lo := int64(-1)
	for x := range byNum {
		if lo < 0 || x < lo {
			lo = x
		}
	}

	// A staged branch continues with the next window, but only if this window
	// really continues it: the first new block names the staged tip as its
	// parent. Anything else (another branch, the next block of our own chain)
	// is judged on its own and the stale stage is dropped.
	var pre []cand
	var preBytes int64
	start := int64(-1)
	n.chainState.mu.Lock()
	staged, stagedBytes := n.chainState.staged, n.chainState.stagedBytes
	n.chainState.mu.Unlock()
	if len(staged) > 0 {
		tipc := staged[len(staged)-1]
		// ... and the stage must still hang on our chain: the block it forks from
		// may have changed since it was kept.
		stillOurs := staged[0].blk.Header.LastBlockHash == crypto.IDHashFile(n.Lay.BlockFile(staged[0].blk.Header.Number-1))
		if raw, ok := byNum[lo]; ok && stillOurs && lo == tipc.blk.Header.Number+1 && parentOf(raw) == tipc.hash {
			pre = append(pre, staged...)
			preBytes = stagedBytes
			start = staged[0].blk.Header.Number
		} else {
			n.clearStaged()
		}
	}
	var nums []int64
	if start < 0 {
		for x := range byNum {
			nums = append(nums, x)
		}
		sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
		for _, x := range nums {
			if x <= last && crypto.IDHashBytes(byNum[x]) == crypto.IDHashFile(n.Lay.BlockFile(x)) {
				continue // already ours
			}
			start = x
			break
		}
		if start < 0 {
			// The window holds only blocks we have. While a fork is being
			// looked for, the fork may lie after it: go on from its end
			// (FIX: the doubling probe alone skipped the stretch between two
			// windows). When the window reaches our tip, or the peer has
			// nothing after it, there is nothing to find.
			// An empty answer (a peer with nothing beyond what it was asked
			// for) holds no block at all: there is nothing to continue from.
			hi := int64(-1)
			if len(nums) > 0 {
				hi = nums[len(nums)-1]
			}
			n.chainState.mu.Lock()
			probing := n.chainState.probe
			if probing && hi >= 0 && hi < last {
				n.chainState.probeResume = hi
			} else {
				probing = false
			}
			n.chainState.mu.Unlock()
			if !probing {
				n.setProbe(false)
			}
			n.clearStaged()
			return 0, nil
		}
		if start > last+1 || start < 1 {
			return 0, nil // not contiguous with anything we hold
		}
	}
	fork := start - 1 // last block we keep

	// ---- phase 1: seals, links, scores; no state is touched ----
	prev := n.Blocks.Header(fork)
	prevHash := crypto.IDHashFile(n.Lay.BlockFile(fork))
	if len(pre) > 0 {
		prev, prevHash = pre[len(pre)-1].blk.Header, pre[len(pre)-1].hash
	}
	nStaged := len(pre)
	now := n.UTCTime()
	var firstErr error
	for num := start + int64(len(pre)); ; num++ {
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
		// FIX: the seal is checked before the link. A block that is not sealed
		// by a listed proposer is no sibling on another branch, whatever its
		// parent says: it is reported as ErrUnsealed so the sync layer can
		// strike the peer at once instead of treating it as a fork.
		var idx int
		if err == nil {
			if !blk.V2 || len(blk.Keys) != len(blk.Orders) {
				err = errors.Join(ErrUnsealed, bad("block has no authentication trailer"))
			} else if idx, err = n.checkSeal(blk); err != nil {
				err = errors.Join(ErrUnsealed, err)
			}
		}
		if err == nil && blk.Header.LastBlockHash != prevHash {
			err = bad("parent hash %q != %q", blk.Header.LastBlockHash, prevHash)
			if len(pre) == 0 {
				err = errors.Join(ErrForkParent, err)
			}
		}
		// FIX(F-8): what a pre-signed run could use to fill memory is checked
		// before it is kept: the slot, the clock, the size and the total.
		if err == nil && (blk.Header.TimeStart != prev.TimeEnd+1 || blk.Header.TimeEnd <= blk.Header.TimeStart ||
			blk.Header.TimeEnd%consensus.SecondsPerBlock != 0) {
			err = bad("time slot of block %d", num)
		}
		if err == nil && blk.Header.TimeEnd > now+5 {
			err = bad("block %d is from the future", num)
		}
		if err == nil && (len(pre) >= maxStaged || preBytes+int64(len(raw)) > maxStagedBytes) {
			err = errStagingLimit
		}
		if err != nil {
			firstErr = err
			break
		}
		preBytes += int64(len(raw))
		pre = append(pre, cand{blk: blk, raw: raw, hash: crypto.IDHashBytes(raw),
			score: BlockScore(k, idx, SlotOf(blk.Header.TimeEnd), SlotOf(prev.TimeEnd))})
		prev, prevHash = blk.Header, pre[len(pre)-1].hash
	}
	if len(pre) == nStaged {
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
		ours = n.oursScore(start, last)
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
			if firstErr == nil {
				n.chainState.mu.Lock()
				n.chainState.staged, n.chainState.stagedBytes = pre, preBytes
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
	replaying := n.chainState.replaying
	if !replaying {
		// A replay from the journal must not touch it: a second crash has to
		// find the same stage-2 journal and blocks again.
		defer n.dropEvalSnapshots()
	}
	if err := n.snapshot("tip"); err != nil {
		return 0, err
	}
	if !replaying {
		if err := n.beginJournal("tip", last); err != nil {
			return 0, err
		}
	}
	putBack := func() {
		n.Summary.ResetBlockRecords()
		if err := n.restoreSnapshot("tip"); err != nil {
			// The live state is ahead of the chain and cannot be put back. The
			// journal stays: the next start restores the snapshot.
			n.markCorrupt()
			return
		}
		if !replaying {
			n.endJournal()
		}
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
	// The orders of the blocks this branch replaces go back to the pool once
	// it is in place; they are kept in the journal until then, because the old
	// blocks are deleted past the commit point.
	var abandoned map[int64][]byte
	if start <= last && !replaying {
		abandoned = n.abandonedRaw(start, last, cands[len(cands)-1].blk.Header.TimeStart)
	}
	if !replaying {
		if err := n.commitJournal("c"+codec.IntToStr(start), last, start, blocks, abandoned); err != nil {
			putBack()
			return 0, err
		}
	}
	// Past the commit point the old branch is gone for good: its undo data
	// goes with it, so no label of the abandoned branch can be used later.
	for b := last; b >= start; b-- {
		_ = removeAll(n.undoDir(codec.IntToStr(b)))
	}
	storage.Crash("pre-writecands")
	if err := n.writeCands(start, last, cands); err != nil {
		// The journal is durable; replay it now, or leave it to the next start.
		n.failedCommit()
		return 0, err
	}
	// The new undo data is in place before the journal is dropped: a crash
	// between the two replays the journal and builds it again.
	for _, c := range cands {
		n.promoteSnapshot(c.blk.Header.Number)
	}
	// The pool follows the chain on every node, builder or not.
	var mined []map[string]bool
	for _, c := range cands {
		mined = append(mined, minedIDs(c.blk.Orders))
	}
	all := map[string]bool{}
	for _, m := range mined {
		for id := range m {
			all[id] = true
		}
	}
	n.pruneMined(all, cands[len(cands)-1].blk.Header)
	// The orders of the replaced blocks come back before the journal is
	// dropped: until then a crash finds them in it.
	n.readmit(abandoned)
	if !replaying {
		n.endJournal()
	}
	tip := start + int64(len(cands)) - 1
	n.Summary.SetLastOp(tip)
	n.Summary.SetHash()
	n.Headers.SetHash()
	n.noteTip(tip)
	n.pruneSnapshots(tip)
	n.setProbe(false)
	n.clearStaged()
	n.RefreshWalletBalances()
	// A new period begins: reports and lists of the old one are void.
	n.ClearMNsChecks()
	n.ClearMNsList()
	n.ClearReceivedMNs()
	if start <= last {
		n.logf("console", "Adopted a heavier branch from block "+codec.IntToStr(start))
	}
	return len(cands), firstErr
}

// parentOf is the parent hash a raw block names, "" when it cannot be read.
func parentOf(raw []byte) string {
	b, err := storage.DecodeBlock(raw)
	if err != nil {
		return ""
	}
	return b.Header.LastBlockHash
}

// oursScore is the score of our blocks from start to last. It is cached for
// the duration of a stage: our chain does not change while a branch is
// compared with it, and re-reading every block per window is quadratic.
func (n *Node) oursScore(start, last int64) int64 {
	key := codec.IntToStr(start) + ":" + codec.IntToStr(last) + ":" + n.tipHashAt(last)
	n.chainState.mu.Lock()
	if n.chainState.oursKey == key {
		v := n.chainState.oursVal
		n.chainState.mu.Unlock()
		return v
	}
	n.chainState.mu.Unlock()
	var sum int64
	for b := start; b <= last; b++ {
		sum += n.blockScoreAt(b)
	}
	n.chainState.mu.Lock()
	n.chainState.oursKey, n.chainState.oursVal = key, sum
	n.chainState.mu.Unlock()
	return sum
}

// writeCands replaces our blocks above the fork with the candidates. The
// blocks database follows the blocks: the records of the abandoned branch go,
// the records of the new blocks come.
func (n *Node) writeCands(start, last int64, cands []cand) error {
	for b := last; b >= start; b-- {
		n.Blocks.Delete(b)
	}
	if start <= last {
		if err := n.dbRollback(start - 1); err != nil {
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
		if err := n.indexBlock(c.blk); err != nil {
			return err
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

// promoteSnapshot makes the evaluation snapshot of a block its undo snapshot.
// It is a copy: the journal of the change may still name the evaluation
// snapshot as its restore point, and it must stay usable until the journal is
// dropped. A crash leaves the old undo data or none, never a half copy under
// the final name.
func (n *Node) promoteSnapshot(num int64) {
	src, dst := n.undoDir("c"+codec.IntToStr(num)), n.undoDir(codec.IntToStr(num))
	tmp := dst + ".new"
	_ = removeAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return
	}
	for name := range n.stateFiles() {
		if err := copyFileOrEmpty(filepath.Join(src, name), filepath.Join(tmp, name)); err != nil {
			_ = removeAll(tmp)
			return
		}
	}
	syncDir(tmp)
	storage.Crash("promo-pre")
	_ = removeAll(dst)
	storage.Crash("promo-mid")
	_ = renameDir(tmp, dst)
}

// dropEvalSnapshots removes the scratch snapshots of a branch evaluation.
func (n *Node) dropEvalSnapshots() {
	if storage.Crashed {
		return
	}
	entries, _ := os.ReadDir(filepath.Join(n.Lay.Root, "UNDO"))
	for _, e := range entries {
		if nm := e.Name(); nm == "tip" || (len(nm) > 1 && nm[0] == 'c') || strings.HasSuffix(nm, ".new") {
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
		n.mustRestore(label)
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
		n.mustRestore(label)
		return "", false, err
	}
	return n.Summary.Hash(), moved, nil
}

// mustRestore puts a snapshot back. When that fails the live state is ahead
// of the chain and nothing here can fix it: the node stops (the journal is
// still there, so the next start restores the state).
func (n *Node) mustRestore(label string) {
	if err := n.restoreSnapshot(label); err != nil {
		n.markCorrupt()
		n.logf("exceps", "state could not be restored: "+err.Error())
	}
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
