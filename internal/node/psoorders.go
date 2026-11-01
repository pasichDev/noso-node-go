package node

import (
	"errors"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// PSO orders. A PSO (nosopsos.pas) is a record of psos.dat: owner, mode, expiry
// and a parameter text. The original had no way to create one on the network;
// its `newpso` command changed one node's file. Here a PSO is created and
// removed by signed orders that a proposer mines into a block, so every node
// applies the same change at the same block and psos.dat stays part of the
// state root:
//
//   - NEWPSO: Reference is the mode (a decimal 1..65535), Params the parameter
//     text (types.ValidPSOParams), Receiver the fixed word "null", no amount,
//     the custom-order fee. Applied with AddNewPSO semantics: owner is the
//     sender, expiry is the number of the block the order extends plus 2016.
//   - CLRPSO: removes the PSOs of the sender, and only those.
//
// A PSO order is a single-line order like CUSTOM: OrderLines 1, TrxLine 1,
// OrderID derived from its transfer id, the params signed with the rest.
const (
	PSONew   = "NEWPSO"
	PSOClear = "CLRPSO"
	// psoNull fills the fields a PSO order does not use.
	psoNull = "null"
)

func isPSOOrder(t string) bool { return t == PSONew || t == PSOClear }

// psoMode reads the mode of a NEWPSO order: the canonical decimal 1..65535.
func psoMode(ref string) (int, bool) {
	v, ok := codec.StrToInt64(ref)
	if !ok || v < 1 || v > 65535 || codec.IntToStr(v) != ref {
		return 0, false
	}
	return int(v), true
}

// psoShape is the stateless rule of a PSO order, with the fee it must pay.
func psoShape(o types.Order, fee int64) bool {
	if o.AmmountFee != fee || o.AmmountTrf != 0 || o.Receiver != psoNull {
		return false
	}
	switch o.OrderType {
	case PSONew:
		_, ok := psoMode(o.Reference)
		return ok && types.ValidPSOParams(o.Params)
	case PSOClear:
		return o.Reference == psoNull && o.Params == ""
	}
	return false
}

// NewPSOOrder builds and signs a NEWPSO order for a wallet address.
func (n *Node) NewPSOOrder(addr string, mode int, params string) (types.Order, error) {
	if mode < 1 || mode > 65535 {
		return types.Order{}, errors.New("the mode is a number from 1 to 65535")
	}
	if !types.ValidPSOParams(params) {
		return types.Order{}, errors.New("the parameters are label:value pairs separated by ';' (labels of up to 8 letters or digits, values of up to 64 letters, digits, '.', '_' or '-'), at most 255 characters and 16 pairs")
	}
	return n.signPSO(addr, PSONew, codec.IntToStr(int64(mode)), params)
}

// ClearPSOsOrder builds and signs a CLRPSO order for a wallet address.
func (n *Node) ClearPSOsOrder(addr string) (types.Order, error) {
	return n.signPSO(addr, PSOClear, psoNull, "")
}

func (n *Node) signPSO(addr, typ, ref, params string) (types.Order, error) {
	idx := n.Wallet.IndexOf(addr)
	if idx < 0 {
		return types.Order{}, errors.New("not an address of this wallet")
	}
	w := n.Wallet.At(idx)
	if w.PrivateKey == "" {
		return types.Order{}, errors.New("no key for " + addr)
	}
	o := types.Order{OrderLines: 1, OrderType: typ, TimeStamp: n.UTCTime(), Reference: ref, TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: psoNull,
		AmmountFee: consensus.GetCustFee(n.MyLastBlock() + 1), Params: params}
	SignOrder(n.ChainID(), &o, w.PrivateKey)
	o.OrderID = SingleOrderID(o.TrfrID)
	o.Normalize()
	return o, nil
}

// PTCPSO admits a NEWPSO or CLRPSO order to the pool, like PTCCustom does for
// a CUSTOM order, and returns 0 or the first error code.
func (n *Node) PTCPSO(line string) int { return n.ptcPSO(line, true) }

func (n *Node) ptcPSO(line string, announce bool) int {
	o, ok := types.ParseOrder(line)
	if !ok {
		return 17
	}
	addr := crypto.GetAddressFromPublicKey(o.Sender, 0)
	code := 0
	if !isPSOOrder(o.OrderType) {
		code = 16
	}
	if addr != o.Address {
		code = 1
	}
	if !psoShape(o, consensus.GetCustFee(n.MyLastBlock()+1)) {
		code = 9
	}
	if n.AddressAvailable(addr) < o.AmmountFee {
		code = 2
	}
	if n.TranxAlreadyPending(o.TrfrID) {
		code = 3
	}
	if o.TimeStamp < n.LastBlockData().TimeStart {
		code = 4
	}
	if n.TrxSeenRecently(o.TrfrID) {
		code = 5
	}
	if o.OrderType == PSONew && n.PSOs.CountOwner(addr)+n.pendingPSOCount(addr) >= consensus.MaxPSOPerOwner {
		code = 6
	}
	if o.OrderID != SingleOrderID(o.TrfrID) {
		code = 12
	}
	if c := VerifyOrder(n.ChainID(), o); c != 0 {
		code = c
	}
	if code == 0 {
		op := codec.GetOpData(line)
		n.AddPool(o)
		if announce && n.Broadcast != nil && n.serverActive() {
			n.Broadcast(PTCHeader(n) + op)
		}
	}
	return code
}

// pendingPSOCount is the number of NEWPSO orders of addr waiting in the pool.
func (n *Node) pendingPSOCount(addr string) int {
	c := 0
	for _, o := range n.PendingCopy() {
		if o.OrderType == PSONew && o.Address == addr {
			c++
		}
	}
	return c
}
