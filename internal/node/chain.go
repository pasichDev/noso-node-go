package node

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Chain rules of this port (FIX(M-10, C-03)). The original network had no
// fork rule: every node built every block and the 5-character vote of the
// seeds decided which copy survived. Here a chain is made of blocks sealed
// by authorised proposers (a signature over the whole block), every node
// verifies every block it stores, and a fork is settled by a deterministic
// weight that anyone can recompute from the blocks alone.

// ErrNoProposers is returned when a peer block arrives at a node that has no
// proposer list: nothing can be authenticated, so nothing is accepted.
var ErrNoProposers = errors.New("no proposer keys configured: peer blocks cannot be authenticated")

// ErrCorrupt is returned once local data was found inconsistent and could not
// be repaired; the node stops touching its chain until it is rebuilt. The text
// says "finality horizon" for the 20-block guard of the operator commands
// (undoblock, removeblocks, replay repair), which is not a finality of the
// chain: fork choice has none (docs/consensus.md). The wording stays because
// the network package matches it.
var ErrCorrupt = errors.New("local chain data inconsistent below the finality horizon")

const proposersFile = "proposers.txt"

// Proposers returns the ordered list of authorised proposer public keys.
func (n *Node) Proposers() []string {
	n.chainState.mu.Lock()
	defer n.chainState.mu.Unlock()
	return append([]string(nil), n.chainState.proposers...)
}

// SetProposers stores the proposer list (one public key per line, in rank
// order) in the data directory. FIX(re2 7): the list is fixed for the life of
// a chain. Every block commits to its digest (Solution), so a node whose file
// differs refuses block 1 and says why, and once the chain has a block the
// list can no longer be replaced by anything with another digest. A rotation
// is a new chain (docs/consensus.md).
func (n *Node) SetProposers(keys []string) error {
	clean, err := cleanProposers(keys)
	if err != nil {
		return err
	}
	if len(clean) == 0 {
		return errors.New("empty proposer list")
	}
	if cur := n.Proposers(); len(cur) > 0 && n.MyLastBlock() >= 1 && proposersDigest(cur) != proposersDigest(clean) {
		return errors.New("the proposer list is fixed once the chain has blocks")
	}
	if d, ok := n.committedDigest(); ok && d != proposersDigest(clean) {
		return errors.New("proposer list does not match the one the chain commits to")
	}
	if err := storage.WriteFileAtomic(filepath.Join(n.Lay.Root, proposersFile), []byte(strings.Join(clean, "\n")+"\n")); err != nil {
		return err
	}
	n.chainState.mu.Lock()
	n.chainState.proposers = clean
	n.chainState.mu.Unlock()
	return nil
}

// cleanProposers validates a list: every entry a public key, no duplicates.
func cleanProposers(keys []string) ([]string, error) {
	var clean []string
	seen := map[string]bool{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if seen[k] {
			return nil, errors.New("duplicate proposer key: " + k)
		}
		if crypto.GetAddressFromPublicKey(k, 0) == "" || len(k) > 120 {
			return nil, errors.New("not a public key: " + k)
		}
		if _, ok := crypto.DecodeBase64Strict(k); !ok {
			return nil, errors.New("proposer key is not canonical Base64: " + k)
		}
		seen[k] = true
		clean = append(clean, k)
	}
	return clean, nil
}

// proposersDigest is what every block commits to.
func proposersDigest(keys []string) string {
	return crypto.SHA256String("PROPOSERS1\n" + strings.Join(keys, "\n"))
}

// committedDigest is the proposer digest the chain commits to (block 1).
func (n *Node) committedDigest() (string, bool) {
	if n.MyLastBlock() < 1 {
		return "", false
	}
	blk, err := n.Blocks.Read(1)
	if err != nil || !blk.V2 {
		return "", false
	}
	_, d, ok := parseSolution(blk.Header.Solution)
	return d, ok
}

// loadProposers reads proposers.txt. A missing file is allowed only for a
// chain that has no block yet (a node still to be configured: it neither
// builds nor accepts anything). A file that cannot be read, is empty, has a
// bad or repeated key, or does not match what the chain commits to is a hard
// error: the node must not guess its way into another chain.
func (n *Node) loadProposers() error {
	raw, err := os.ReadFile(filepath.Join(n.Lay.Root, proposersFile))
	if errors.Is(err, os.ErrNotExist) {
		if n.MyLastBlock() >= 1 {
			return errors.New("proposers.txt is missing but the chain has blocks")
		}
		return nil
	}
	if err != nil {
		return err
	}
	keys, err := cleanProposers(strings.Split(string(raw), "\n"))
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("proposers.txt is empty")
	}
	if d, ok := n.committedDigest(); ok && d != proposersDigest(keys) {
		return errors.New("proposers.txt does not match the list the chain commits to")
	}
	n.chainState.mu.Lock()
	n.chainState.proposers = keys
	n.chainState.mu.Unlock()
	return nil
}

func indexOfKey(keys []string, k string) int {
	for i, x := range keys {
		if x == k {
			return i
		}
	}
	return -1
}

// sealer returns the proposer slot and wallet entry this node signs with: the
// first wallet key that is on the proposer list.
func (n *Node) sealer() (idx int, w types.Wallet, ok bool) {
	props := n.Proposers()
	for i := 0; i < n.Wallet.Len(); i++ {
		w = n.Wallet.At(i)
		if w.PrivateKey != "" {
			if idx = indexOfKey(props, w.PublicKey); idx >= 0 {
				return idx, w, true
			}
		}
	}
	return -1, types.Wallet{}, false
}

// sealDigest is what a proposer signs: a hash of the block body and keys.
func sealDigest(b *storage.Block) string { return crypto.SHA256String(string(b.SigningBytes())) }

func sealBlock(b *storage.Block, pub, priv string) {
	b.V2, b.SealKey = true, pub
	b.SealSig = crypto.SignCanonical(priv, "BLOCKSEAL1", sealDigest(b))
}

// checkSeal verifies the proposer signature and returns the proposer slot.
func (n *Node) checkSeal(b *storage.Block) (int, error) {
	props := n.Proposers()
	if len(props) == 0 {
		return -1, ErrNoProposers
	}
	idx := indexOfKey(props, b.SealKey)
	if idx < 0 {
		return -1, bad("block sealed by a key that is not a proposer")
	}
	if !crypto.VerifyCanonical(b.SealKey, b.SealSig, "BLOCKSEAL1", sealDigest(b)) {
		return -1, bad("proposer signature does not verify")
	}
	return idx, nil
}

// BlockWeight is the weight a block adds to its chain: k for the proposer
// whose turn it is (turn = block time slot mod k, slot = TimeEnd / 600), down
// to 1 for the one furthest from its turn. With a single proposer every block
// weighs 1. Turns follow the clock, not the height, so a proposer that is
// offline only costs its own slots: the next boundary has another turn holder.
func BlockWeight(k, proposerIdx int, slot int64) int64 {
	if k <= 0 || proposerIdx < 0 {
		return 0
	}
	rank := (int64(proposerIdx) - slot) % int64(k)
	if rank < 0 {
		rank += int64(k)
	}
	return int64(k) - rank
}

// SlotOf is the turn number of a block time.
func SlotOf(timeEnd int64) int64 { return timeEnd / consensus.SecondsPerBlock }

// BlockScore is what a block adds to its branch: its weight minus k for every
// slot skipped since its parent. FIX(re2 5): a skipped slot costs a full
// in-turn block, so a proposer that sits on the parent and builds later does
// not tie with the block it replaces.
func BlockScore(k, proposerIdx int, slot, parentSlot int64) int64 {
	w := BlockWeight(k, proposerIdx, slot)
	if w == 0 {
		return 0
	}
	if gap := slot - parentSlot - 1; gap > 0 {
		w -= int64(k) * gap
	}
	return w
}

// Preferred reports whether branch A beats branch B (both measured from the
// same fork point): the higher score wins, then the earlier tip time (the
// proposer that was first in the schedule keeps its block), then the lower tip
// hash. All three are facts of valid blocks, not votes, and nothing here
// depends on the node's own history, so every node picks the same branch.
// With the header pinned (validate.go) the only freedom of a proposer is its
// choice of orders, so grinding the hash is limited to equivocation.
func Preferred(scoreA, timeA int64, tipA string, scoreB, timeB int64, tipB string) bool {
	if scoreA != scoreB {
		return scoreA > scoreB
	}
	if timeA != timeB {
		return timeA < timeB
	}
	return tipA < tipB
}

// InTurn reports whether this node may build the block whose time is
// timestamp: it holds a proposer key and the slot is its turn. Without a
// proposer list nothing is built.
func (n *Node) InTurn(timestamp int64) bool {
	props := n.Proposers()
	if len(props) == 0 {
		return false
	}
	idx, _, ok := n.sealer()
	return ok && int(SlotOf(timestamp)%int64(len(props))) == idx
}

// ---- snapshots and finality ------------------------------------------------

func (n *Node) undoDir(label string) string { return filepath.Join(n.Lay.Root, "UNDO", label) }

// snapshot copies the three consensus state files into UNDO/<label>. The copy
// is on stable storage when it returns: recovery after a crash depends on it.
func (n *Node) snapshot(label string) error {
	dir := n.undoDir(label)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, src := range n.stateFiles() {
		if err := copyFileOrEmpty(src, filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	syncDir(dir)
	syncDir(filepath.Dir(dir))
	return nil
}

// restoreSnapshot puts the files of UNDO/<label> back and reloads them.
func (n *Node) restoreSnapshot(label string) error {
	dir := n.undoDir(label)
	for name, dst := range n.stateFiles() {
		if err := copyFileOrEmpty(filepath.Join(dir, name), dst); err != nil {
			return err
		}
	}
	n.Summary.CreateIndex()
	n.GVTs.Reload()
	n.PSOs.Load()
	return nil
}

func (n *Node) hasSnapshot(label string) bool {
	return storage.Exists(filepath.Join(n.undoDir(label), "sumary.psk"))
}

func (n *Node) stateFiles() map[string]string {
	return map[string]string{"sumary.psk": n.Lay.Summary, "gvts.psk": n.Lay.GVTs, "psos.dat": n.Lay.PSOs}
}

// copyFileOrEmpty copies src to dst atomically and durably; a missing source
// is an empty file.
func copyFileOrEmpty(src, dst string) error {
	b, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		b, err = nil, nil
	}
	if err != nil {
		return err
	}
	return storage.WriteFileAtomic(dst, b)
}

// undoKeep is how many per-block snapshots are kept: more than MaxReorgDepth.
const undoKeep = MaxReorgDepth + 12

func (n *Node) pruneSnapshots(tip int64) {
	entries, _ := os.ReadDir(filepath.Join(n.Lay.Root, "UNDO"))
	for _, e := range entries {
		if v := codec.StrToInt64Def(e.Name(), -1); v >= 0 && v <= tip-undoKeep {
			_ = os.RemoveAll(filepath.Join(n.Lay.Root, "UNDO", e.Name()))
		}
	}
}

const highwaterFile = "highwater.seq"

// highwater is the highest tip this node ever reached. FIX(H-04): the
// reorganisation limit is counted against it, so repeated small rollbacks
// cannot add up to a deep one.
func (n *Node) highwater() int64 { return n.readSeq(highwaterFile) }

func (n *Node) noteTip(tip int64) {
	if tip > n.highwater() {
		_ = n.writeSeq(highwaterFile, tip)
	}
}

// Finalized is the height at or below which blocks never change: the highest
// tip ever reached minus MaxReorgDepth.
func (n *Node) Finalized() int64 {
	f := n.highwater() - MaxReorgDepth
	if f < 0 {
		f = 0
	}
	return f
}

func (n *Node) isCorrupt() bool {
	n.chainState.mu.Lock()
	defer n.chainState.mu.Unlock()
	return n.chainState.corrupt
}

func (n *Node) markCorrupt() {
	n.chainState.mu.Lock()
	n.chainState.corrupt = true
	n.chainState.mu.Unlock()
}

// Corrupt reports that local data failed a replay below the finality
// horizon; sync stops trying and the operator must rebuild the node.
func (n *Node) Corrupt() bool { return n.isCorrupt() }
