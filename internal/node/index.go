package node

import (
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// The blocks database (order lookup) follows the chain: the records of a
// block are written when the block is committed and dropped when the block is
// removed, so a lookup finds exactly the orders of the chain we hold, mined
// ones included (FIX: nothing ever called BlocksDB.Update).

// indexBlock records the orders of a committed block.
func (n *Node) indexBlock(b *storage.Block) error {
	if n.DB == nil {
		return nil
	}
	return n.DB.AddBlock(int32(b.Header.Number), b.Orders)
}

// dbRollback drops the records of every block above block.
func (n *Node) dbRollback(block int64) error {
	if n.DB == nil {
		return nil
	}
	if block < 0 {
		block = 0
	}
	return n.DB.RollbackTo(int32(block))
}

// syncBlocksDB makes the database agree with the chain: records of blocks the
// chain no longer has go, blocks it has and the database lacks are indexed.
// The last indexed block is redone, because a crash can leave part of its
// records.
func (n *Node) syncBlocksDB() error {
	if n.DB == nil {
		return nil
	}
	last := n.MyLastBlock()
	if db := int64(n.DB.LastBlock()); db > last {
		if err := n.dbRollback(last); err != nil {
			return err
		}
	}
	if db := int64(n.DB.LastBlock()); db > 0 {
		if err := n.dbRollback(db - 1); err != nil {
			return err
		}
	}
	return n.DB.Update(n.Blocks, last)
}

// OrderBlock is the block that holds a mined order, -1 when the chain has no
// such order.
func (n *Node) OrderBlock(orderID string) int {
	if n.DB == nil {
		return -1
	}
	return n.DB.BlockFromOrder(n.Blocks, orderID)
}

// MinedOrder returns the lines of a mined order.
func (n *Node) MinedOrder(orderID string) []types.Order {
	b := n.OrderBlock(orderID)
	if b < 0 {
		return nil
	}
	var out []types.Order
	for _, o := range n.Blocks.Orders(int64(b)) {
		if o.OrderID == orderID {
			out = append(out, o)
		}
	}
	return out
}

// WalletBalance is the balance of an address as the chain state holds it. The
// wallet file's own Balance field is not maintained by anything; use this (or
// AddressAvailable, which also subtracts what the pool has committed).
func (n *Node) WalletBalance(addr string) int64 { return n.Summary.BalanceIndexed(addr) }

// RefreshWalletBalances copies the chain balance into the Balance field of
// every wallet record, in memory. It runs after every block that is built or
// accepted, so readers of the record (customize, the GUI) see the chain, not
// a number nothing ever wrote (GAP-4).
func (n *Node) RefreshWalletBalances() {
	for _, w := range n.Wallet.All() {
		n.Wallet.SetBalance(w.Hash, n.Summary.BalanceIndexed(w.Hash))
	}
}

// ErrPSOByBlockOnly is the answer to a request to create a PSO outside a block.
var ErrPSOByBlockOnly = nodeError("PSOs are part of the consensus state and change only through blocks; this chain's blocks carry no PSO, so none can be created")

// NewPSO is what the `newpso` command calls. It never writes psos.dat: that
// file is in the state root, and a local change makes the node refuse the next
// block. Until blocks can carry PSOs it only reports why nothing was done.
func (n *Node) NewPSO() error { return ErrPSOByBlockOnly }
