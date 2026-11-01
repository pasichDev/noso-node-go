package node

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Orders of abandoned blocks. When a heavier branch replaces some of our
// blocks, the user orders of the abandoned blocks that are still valid on the
// new tip go back into the pool, through the same admission checks as an order
// that arrives from a peer. The pool is not consensus state: nothing here
// touches the chain, and an order that fails a check is dropped, as it would
// be if it arrived now.
//
// The raw abandoned blocks are written into the journal of the change, so a
// crash after the commit point (when the old blocks may already be deleted)
// still finds them at the next start.

const (
	// abandonedDir is the part of the journal directory that holds the
	// abandoned blocks. Its entries do not end in ".blk" at the top level, so
	// recovery does not count them as blocks of the change.
	abandonedDir = "abandoned"
	// maxReadmitBlocks bounds the abandoned blocks kept: an order is only
	// valid for the slot it was signed for, so only the latest few can matter.
	maxReadmitBlocks = 32
)

// abandonedRaw returns the raw blocks start..last that may hold an order that
// is still valid on a tip whose block begins at newTipStart. An order is valid
// from the start of the block interval it was signed for, so an abandoned
// block that ended before the new tip began holds none.
func (n *Node) abandonedRaw(start, last, newTipStart int64) map[int64][]byte {
	out := map[int64][]byte{}
	for b := last; b >= start && len(out) < maxReadmitBlocks; b-- {
		if n.Blocks.Header(b).TimeEnd-60 < newTipStart {
			break
		}
		raw, err := os.ReadFile(n.Lay.BlockFile(b))
		if err != nil {
			break
		}
		out[b] = raw
	}
	return out
}

func (n *Node) abandonedPath() string { return filepath.Join(n.journalDir(), abandonedDir) }

// writeAbandoned stores the abandoned blocks in the journal directory.
func (n *Node) writeAbandoned(raws map[int64][]byte) error {
	if len(raws) == 0 {
		return nil
	}
	if err := os.MkdirAll(n.abandonedPath(), 0o700); err != nil {
		return err
	}
	for num, raw := range raws {
		if err := storage.WriteFileAtomic(filepath.Join(n.abandonedPath(), codec.IntToStr(num)+".blk"), raw); err != nil {
			return err
		}
	}
	syncDir(n.abandonedPath())
	return nil
}

// readAbandoned reads the abandoned blocks of the journal, oldest first.
func (n *Node) readAbandoned() map[int64][]byte {
	out := map[int64][]byte{}
	ents, _ := os.ReadDir(n.abandonedPath())
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".blk") {
			continue
		}
		num := codec.StrToInt64Def(strings.TrimSuffix(name, ".blk"), -1)
		if b, err := os.ReadFile(filepath.Join(n.abandonedPath(), name)); err == nil && num >= 0 {
			out[num] = b
		}
	}
	return out
}

// readmit puts the user orders of abandoned raw blocks back into the pool.
// The caller holds the chain lock and has already applied the new branch.
func (n *Node) readmit(raws map[int64][]byte) int {
	nums := make([]int64, 0, len(raws))
	for num := range raws {
		nums = append(nums, num)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	added := 0
	for _, num := range nums {
		blk, err := storage.DecodeBlock(raws[num])
		if err != nil || !blk.V2 || len(blk.Keys) != len(blk.Orders) {
			continue
		}
		var user []types.Order
		for i, o := range blk.Orders {
			if o.OrderType == "PROJCT" {
				continue
			}
			o.Block = 0
			o.Sender = blk.Keys[i] // pool form: the full public key
			o.Normalize()
			user = append(user, o)
		}
		for i := 0; i < len(user); {
			cnt := 1
			if user[i].OrderType == "TRFR" {
				cnt = int(user[i].OrderLines)
			}
			if cnt < 1 || cnt > 30 || i+cnt > len(user) {
				i++
				continue
			}
			if n.admitAgain(user[i : i+cnt]) {
				added += cnt
			}
			i += cnt
		}
	}
	return added
}

// admitAgain admits one wire order (all its lines) through the normal checks
// of its kind, without announcing it.
func (n *Node) admitAgain(group []types.Order) bool {
	switch group[0].OrderType {
	case "TRFR":
		line := PTCHeader(n) + "ORDER " + codec.IntToStr(int64(len(group))) + " "
		for _, o := range group {
			line += "$" + types.StringFromOrder(o) + " "
		}
		return n.ptcOrder(strings.TrimSpace(line), false) == group[0].OrderID
	case "CUSTOM":
		return n.ptcCustom("$"+types.StringFromOrder(group[0]), false) == 0
	case "SNDGVT":
		return n.ptcSendGVT("$"+types.StringFromOrder(group[0]), false) == 0
	}
	return false
}
