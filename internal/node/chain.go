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

// ErrCorrupt is returned once local data was found inconsistent below the
// finality horizon; the node stops touching its chain until it is rebuilt.
var ErrCorrupt = errors.New("local chain data inconsistent below the finality horizon")

const proposersFile = "proposers.txt"

// Proposers returns the ordered list of authorised proposer public keys.
func (n *Node) Proposers() []string {
	n.chainState.mu.Lock()
	defer n.chainState.mu.Unlock()
	return append([]string(nil), n.chainState.proposers...)
}

// SetProposers stores the proposer list (one public key per line, in rank
// order) in the data directory. The list is chain configuration: every node
// of a chain must hold the same list in the same order.
func (n *Node) SetProposers(keys []string) error {
	var clean []string
	seen := map[string]bool{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		if crypto.GetAddressFromPublicKey(k, 0) == "" || len(k) > 120 {
			return errors.New("not a public key: " + k)
		}
		seen[k] = true
		clean = append(clean, k)
	}
	if err := os.WriteFile(filepath.Join(n.Lay.Root, proposersFile), []byte(strings.Join(clean, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	n.chainState.mu.Lock()
	n.chainState.proposers = clean
	n.chainState.mu.Unlock()
	return nil
}

func (n *Node) loadProposers() {
	raw, err := os.ReadFile(filepath.Join(n.Lay.Root, proposersFile))
	if err != nil {
		return
	}
	var keys []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			keys = append(keys, l)
		}
	}
	n.chainState.proposers = keys
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

// Preferred reports whether chain A beats chain B: the heavier one wins, and
// equal weight is settled by the lower tip hash. Both inputs are facts about
// valid blocks, not votes. A proposer can grind its own tip hash, but only
// among blocks it is itself allowed to sign at that weight, so grinding can
// only pick between equally weighted blocks of the authorised set.
func Preferred(weightA int64, tipA string, weightB int64, tipB string) bool {
	if weightA != weightB {
		return weightA > weightB
	}
	return tipA < tipB
}

// InTurn reports whether this node may build the block whose time is
// timestamp: it holds a proposer key and the slot is its turn. A node with no
// proposer list at all builds unsealed blocks (a standalone chain nobody can
// join, since peers refuse unauthenticated blocks).
func (n *Node) InTurn(timestamp int64) bool {
	props := n.Proposers()
	if len(props) == 0 {
		return true
	}
	idx, _, ok := n.sealer()
	return ok && int(SlotOf(timestamp)%int64(len(props))) == idx
}

// ---- snapshots and finality ------------------------------------------------

func (n *Node) undoDir(label string) string { return filepath.Join(n.Lay.Root, "UNDO", label) }

// snapshot copies the three consensus state files into UNDO/<label>.
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

func copyFileOrEmpty(src, dst string) error {
	b, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		b, err = nil, nil
	}
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
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
