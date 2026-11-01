package node

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// Crash atomicity (FIX(re2 2)). The chain is the blocks directory plus the
// headers file; the state is the summary, GVT and PSO files. They are separate
// files and cannot be changed in one step, so every change of the chain goes
// through a journal and the state is never trusted past the chain:
//
//  1. a durable snapshot of the state at the point the change starts from
//     (UNDO/<label>) and a stage-1 journal naming it and the current tip;
//  2. the blocks are validated and applied to the live state files;
//  3. the stage-2 journal is written: the snapshot to start from, the first and
//     last block and the raw blocks of the change (JOURNAL.d). This file is the
//     single commit point: from here the change WILL happen;
//  4. old blocks above the fork are removed, the new blocks and their header
//     records are written, the journal is removed.
//
// After a crash, recovery restores the snapshot and either discards the change
// (stage 1) or runs the journalled blocks through the normal acceptance code
// again (stage 2). Either way the state equals the chain, and a block that is
// delivered again meets a state that has not applied it. As a second line of
// defence the node checks at every start that the state matches the tip block's
// state root and replays the chain when it does not.

const (
	journalFile = "JOURNAL"
	journalDir  = "JOURNAL.d"
)

type journal struct {
	Restore string `json:"restore"` // snapshot label to restore
	Last    int64  `json:"last"`    // tip when the change began
	Start   int64  `json:"start"`   // first block of the change (stage 2)
	Count   int    `json:"count"`   // blocks in JOURNAL.d (stage 2)
}

func (n *Node) journalPath() string { return filepath.Join(n.Lay.Root, journalFile) }
func (n *Node) journalDir() string  { return filepath.Join(n.Lay.Root, journalDir) }

func (n *Node) writeJournal(j journal) error {
	b, _ := json.Marshal(j)
	return storage.WriteFileAtomic(n.journalPath(), b)
}

// beginJournal is stage 1: the snapshot <restore> holds the state of the
// chain whose tip is last.
func (n *Node) beginJournal(restore string, last int64) error {
	return n.writeJournal(journal{Restore: restore, Last: last})
}

// commitJournal is stage 2, the commit point.
func (n *Node) commitJournal(restore string, last, start int64, blocks map[int64][]byte) error {
	if err := os.RemoveAll(n.journalDir()); err != nil {
		return err
	}
	if err := os.MkdirAll(n.journalDir(), 0o700); err != nil {
		return err
	}
	storage.Crash("cj-dir")
	for num, raw := range blocks {
		if err := storage.WriteFileAtomic(filepath.Join(n.journalDir(), codec.IntToStr(num)+".blk"), raw); err != nil {
			return err
		}
	}
	syncDir(n.journalDir())
	syncDir(n.Lay.Root)
	return n.writeJournal(journal{Restore: restore, Last: last, Start: start, Count: len(blocks)})
}

func (n *Node) endJournal() {
	storage.Crash("ej-pre")
	_ = os.Remove(n.journalPath())
	storage.Crash("ej-mid")
	_ = os.RemoveAll(n.journalDir())
	storage.Crash("ej-post")
	syncDir(n.Lay.Root)
}

// recoverLocked completes or discards an interrupted change, then checks that
// the state belongs to the chain and replays the chain when it does not.
func (n *Node) recoverLocked() error {
	raw, err := os.ReadFile(n.journalPath())
	if err == nil {
		var j journal
		if json.Unmarshal(raw, &j) != nil || j.Restore == "" || strings.ContainsAny(j.Restore, "/\\.") || !n.hasSnapshot(j.Restore) {
			n.endJournal()
			return n.repairLocked("journal unusable")
		}
		blocks := map[int64][]byte{}
		if j.Count > 0 {
			ents, _ := os.ReadDir(n.journalDir())
			for _, e := range ents {
				name := e.Name()
				if !strings.HasSuffix(name, ".blk") {
					continue
				}
				num := codec.StrToInt64Def(strings.TrimSuffix(name, ".blk"), -1)
				if b, err := os.ReadFile(filepath.Join(n.journalDir(), name)); err == nil && num >= 0 {
					blocks[num] = b
				}
			}
		}
		cut := j.Last + 1 // first block that did not exist when the change began
		if j.Count > 0 && j.Start < cut {
			cut = j.Start
		}
		if err := n.restoreSnapshot(j.Restore); err != nil {
			return err
		}
		n.cutChainFrom(cut)
		if j.Count > 0 && len(blocks) == j.Count {
			// Run the journalled blocks again. They extend the chain now. The
			// journal stays as it is until the replay is complete, so a second
			// crash finds the same journal.
			n.chainState.replaying = true
			_, err := n.acceptRunLocked(blocks)
			n.chainState.replaying = false
			if err != nil {
				n.logf("exceps", "journal replay: "+err.Error())
			}
		}
		n.endJournal()
		n.dropEvalSnapshots()
		n.UpdateMyData()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return n.repairLocked("")
}

// cutChainFrom removes the blocks and header records from number from upward.
func (n *Node) cutChainFrom(from int64) {
	if from < 1 {
		from = 1
	}
	for b := n.Blocks.LastUpdated(); b >= from; b-- {
		n.Blocks.Delete(b)
	}
	last := n.Blocks.LastUpdated()
	for int64(n.Headers.Height()) > last && n.Headers.RemoveLast() {
	}
	n.SetMyLastBlock(last)
	_ = n.dbRollback(last)
	n.UpdateMyData()
}

// repairLocked checks that headers and state agree with the blocks.
func (n *Node) repairLocked(why string) error {
	last := n.MyLastBlock()
	for int64(n.Headers.Height()) > last && n.Headers.RemoveLast() {
	}
	healthy := int64(n.Headers.Height()) == last && n.Summary.LastOp() == last
	if healthy {
		// The tip file must be the block the headers file recorded, and a
		// block of a chain born here must still decode (a truncated or
		// damaged tip passed the state-root test, which skipped what it
		// could not read).
		recs := n.Headers.All()
		if int64(len(recs)) != last+1 || recs[last].BlockHash != crypto.IDHashFile(n.Lay.BlockFile(last)) {
			healthy = false
		}
	}
	if healthy && last >= 1 {
		blk, err := n.Blocks.Read(last)
		if err != nil || !blk.V2 {
			healthy = false
		} else if root, _, ok := parseSolution(blk.Header.Solution); !ok || root != n.stateRoot() {
			healthy = false
		}
	}
	if healthy {
		return n.syncBlocksDB()
	}
	n.logf("console", "State does not match the chain, replaying it "+why)
	err := n.rebuildLocked(last, func(i int64) {
		// The headers file is rewritten with the replay: one record per block.
		if i == 0 {
			n.Headers.Create()
		}
		n.Headers.Add(i, crypto.IDHashFile(n.Lay.BlockFile(i)), n.Summary.Hash())
	})
	if err != nil {
		n.markCorrupt()
		n.logf("exceps", "replay at start failed: "+err.Error())
		return errors.Join(ErrCorrupt, err)
	}
	n.UpdateMyData()
	return n.syncBlocksDB()
}

// stateRoot is the commitment every sealed block carries: the hash of the
// three consensus state files after the block was applied.
func (n *Node) stateRoot() string {
	var parts []string
	names := make([]string, 0, 3)
	files := n.stateFiles()
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := os.ReadFile(files[name])
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			// An unreadable file must not look like an empty one: the root
			// then matches nothing a block can carry.
			return "UNREADABLE " + name
		}
		parts = append(parts, name, crypto.SHA256String(string(b)))
	}
	return crypto.SHA256String("STATEROOT1|" + strings.Join(parts, "|"))
}

// The Solution field of a sealed block is not free text. It holds the state
// root and the digest of the proposer list, so nothing in the header can be
// ground and a node that is on another state or another chain sees it at once.
const solutionPrefix = "NSR1 "

func solutionFor(root, digest string) string { return solutionPrefix + root + " " + digest }

func parseSolution(s string) (root, digest string, ok bool) {
	if !strings.HasPrefix(s, solutionPrefix) {
		return "", "", false
	}
	f := strings.Split(s, " ")
	if len(f) != 3 || len(f[1]) != 64 || len(f[2]) != 64 {
		return "", "", false
	}
	return f[1], f[2], true
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		if !storage.NoSync() {
			_ = d.Sync()
		}
		_ = d.Close()
	}
}
