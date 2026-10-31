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
// request: our tip normally, MaxReorgDepth earlier (never into the finalized
// part) when a fork is suspected.
func (n *Node) BlocksRequestFrom() int64 {
	last := n.MyLastBlock()
	if !n.ForkProbe() {
		return last
	}
	from := last - MaxReorgDepth + 1
	if f := n.Finalized(); from < f {
		from = f
	}
	if from < 0 {
		from = 0
	}
	return from
}

type candidate struct {
	blk     *storage.Block
	raw     []byte
	sumHash string
	moved   bool
}

// acceptRunLocked is the one place where blocks from outside enter the chain
// (FIX(C-03, M-10)). byNum holds raw block files by number. Blocks identical
// to ours are skipped; the first differing block must continue one of our
// blocks (at or above the finality horizon). The run is validated and applied
// block by block against the state at its fork point. It is adopted when it
// extends our tip, or when it is Preferred over our blocks above the fork
// point; otherwise the state is put back untouched. It returns how many
// blocks were stored.
func (n *Node) acceptRunLocked(byNum map[int64][]byte) (int, error) {
	if n.isCorrupt() {
		return 0, ErrCorrupt
	}
	if len(n.Proposers()) == 0 {
		return 0, ErrNoProposers
	}
	var nums []int64
	for k := range byNum {
		nums = append(nums, k)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	last := n.MyLastBlock()
	start := int64(-1)
	for _, k := range nums {
		if k <= last && crypto.IDHashBytes(byNum[k]) == crypto.IDHashFile(n.Lay.BlockFile(k)) {
			continue // already ours
		}
		start = k
		break
	}
	if start < 0 {
		n.setProbe(false)
		return 0, nil
	}
	if start > last+1 || start < 1 {
		return 0, nil // not contiguous with anything we hold
	}
	fork := start - 1 // last block we keep
	if start <= last && fork < n.Finalized() {
		return 0, bad("branch forks at %d, below the finality horizon %d", fork, n.Finalized())
	}

	defer n.dropEvalSnapshots()
	// State of our tip, to come back to when the branch is not taken.
	if err := n.snapshot("tip"); err != nil {
		return 0, err
	}
	putBack := func() {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot("tip")
	}
	if start <= last {
		if !n.hasSnapshot(codec.IntToStr(start)) {
			return 0, bad("no undo data for block %d", start)
		}
		if err := n.restoreSnapshot(codec.IntToStr(start)); err != nil {
			putBack()
			return 0, err
		}
	}
	prev := n.Blocks.Header(fork)
	prevHash := crypto.IDHashFile(n.Lay.BlockFile(fork))
	recent := map[string]bool{}
	for _, o := range n.Blocks.Orders(fork) {
		recent[o.TrfrID] = true
	}
	var cands []candidate
	var firstErr error
	k := len(n.Proposers())
	var weight int64
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
		var sum string
		var moved bool
		if err == nil {
			sum, moved, err = n.evalBlock(blk, prev, prevHash, recent, "c"+codec.IntToStr(num))
		}
		if err != nil {
			firstErr = err
			if len(cands) == 0 && errors.Is(err, ErrInvalidBlock) && num == start && blk != nil &&
				blk.Header.LastBlockHash != prevHash {
				firstErr = errors.Join(ErrForkParent, err)
				n.setProbe(true)
			}
			break
		}
		idx := indexOfKey(n.Proposers(), blk.SealKey)
		weight += BlockWeight(k, idx, SlotOf(blk.Header.TimeEnd))
		cands = append(cands, candidate{blk, raw, sum, moved})
		prev, prevHash = blk.Header, crypto.IDHashBytes(raw)
		recent = map[string]bool{}
		for _, o := range blk.Orders {
			recent[o.TrfrID] = true
		}
	}
	if len(cands) == 0 {
		putBack()
		return 0, firstErr
	}
	if start <= last {
		var ours int64
		for b := start; b <= last; b++ {
			ours += n.blockWeightAt(b)
		}
		if !Preferred(weight, crypto.IDHashBytes(cands[len(cands)-1].raw), ours, n.tipHashAt(last)) {
			putBack()
			n.setProbe(false)
			return 0, firstErr
		}
	}
	// Adopt: drop our blocks above the fork, store the branch.
	for b := last; b >= start; b-- {
		n.Blocks.Delete(b)
	}
	// The headers file may already hold records for these blocks (it can be
	// downloaded first): keep exactly one record per block up to the fork.
	for n.Headers.Height() >= int(start) && n.Headers.RemoveLast() {
	}
	for i, c := range cands {
		num := start + int64(i)
		if err := n.Blocks.Write(c.blk); err != nil || !n.Headers.Add(num, crypto.IDHashBytes(c.raw), c.sumHash) {
			for b := start + int64(i); b >= start; b-- {
				n.Blocks.Delete(b)
			}
			// headers for the blocks written so far are dropped; ours above
			// the fork are gone, so the node resynchronises from the fork.
			for n.Headers.Height() >= int(start) && n.Headers.RemoveLast() {
			}
			putBack()
			n.SetMyLastBlock(n.Blocks.LastUpdated())
			n.UpdateMyData()
			if err == nil {
				err = errHeaderWrite
			}
			return 0, err
		}
		n.promoteSnapshot(num)
	}
	tip := start + int64(len(cands)) - 1
	n.SetMyLastBlock(tip)
	n.Summary.SetLastOp(tip)
	n.UpdateMyData()
	n.Summary.SetHash()
	n.Headers.SetHash()
	n.noteTip(tip)
	n.pruneSnapshots(tip)
	n.setProbe(false)
	if start <= last {
		n.ClearMNsChecks()
		n.ClearMNsList()
		n.logf("console", "Adopted a heavier branch from block "+codec.IntToStr(start))
	}
	return len(cands), firstErr
}

// promoteSnapshot turns the evaluation snapshot of a block into its undo
// snapshot.
func (n *Node) promoteSnapshot(num int64) {
	_ = removeAll(n.undoDir(codec.IntToStr(num)))
	_ = renameDir(n.undoDir("c"+codec.IntToStr(num)), n.undoDir(codec.IntToStr(num)))
}

func (n *Node) blockWeightAt(num int64) int64 {
	blk, err := n.Blocks.Read(num)
	if err != nil || !blk.V2 {
		return 0
	}
	return BlockWeight(len(n.Proposers()), indexOfKey(n.Proposers(), blk.SealKey), SlotOf(blk.Header.TimeEnd))
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
	n.persistDerived(blk.Header.Number, moved)
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
