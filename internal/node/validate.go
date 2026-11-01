package node

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// OutOfTurnGrace is how long after a slot's boundary only its turn holder may
// seal the block of that slot.
const OutOfTurnGrace = 120

// ErrInvalidBlock wraps every block validation failure.
var ErrInvalidBlock = errors.New("invalid block")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidBlock, fmt.Sprintf(format, a...))
}

// checkOrder is the stateless rule for one user order, used by the builder
// before it takes an order and by the validator for every order of a received
// block. The order is in pool form: Sender holds the full public key.
// FIX(C-03): followers re-check the key-address binding, the signature over
// every field and the derived TrfrID, so a proposer cannot spend an account
// whose key it does not hold. Replay protection is the time window (an order
// is only valid in the block interval it was signed for) plus the id test
// against the previous block.
func (n *Node) checkOrder(o types.Order, prev types.BlockHeader, blockTime int64) error {
	switch o.OrderType {
	case "TRFR", "CUSTOM", "SNDGVT", PSONew, PSOClear:
	default:
		return fmt.Errorf("order type %q", o.OrderType)
	}
	if o.AmmountTrf < 0 || o.AmmountFee < 0 {
		return errors.New("negative amount")
	}
	if _, ok := consensus.CheckedAdd(o.AmmountTrf, o.AmmountFee); !ok {
		return errors.New("amount range")
	}
	if !types.ValidReference(o.Reference) {
		return errors.New("reference has characters that are not allowed")
	}
	if o.TimeStamp < prev.TimeStart || o.TimeStamp+60 > blockTime {
		return errors.New("order time outside the block window")
	}
	if o.Sender == "" || len(o.Sender) > 120 {
		return errors.New("missing public key")
	}
	if c := VerifyOrder(n.ChainID(), o); c != 0 {
		return fmt.Errorf("order verification code %d", c)
	}
	switch o.OrderType {
	case "TRFR":
		if !ValidReceiver(o.Receiver) {
			return errors.New("receiver")
		}
	case "CUSTOM":
		if o.AmmountFee != consensus.GetCustFee(prev.Number+1) || o.AmmountTrf != 0 || !ValidAlias(o.Receiver) {
			return errors.New("custom order")
		}
	case PSONew, PSOClear:
		if !psoShape(o, consensus.GetCustFee(prev.Number+1)) {
			return errors.New("pso order")
		}
	case "SNDGVT":
		if _, ok := gvtNumber(o.Reference); !ok || o.AmmountFee != consensus.GetCustFee(prev.Number+1) ||
			o.AmmountTrf != 0 || !ValidReceiver(o.Receiver) {
			return errors.New("gvt order")
		}
	}
	return nil
}

// ValidateBlock checks everything about a block received from a peer that
// does not depend on balances: numbering and parent hash, time slots, the
// proposer seal, reward arithmetic, every order's key, signature, id and time,
// the project payment, the miner and masternode shares. Balances, ownership
// and aliases are checked when the block is applied to the state
// (applyBlockState). The checks reflect the original design flaw FIX(C-03):
// the original stored whatever blocks a peer sent and relied on a
// 5-character vote (mpred.pas:666-686, masterpaskalform.pas:1098-1134).
func (n *Node) ValidateBlock(b *storage.Block, prev types.BlockHeader, prevHash string, recent map[string]bool) error {
	h := b.Header
	if h.Number != prev.Number+1 {
		return bad("number %d after %d", h.Number, prev.Number)
	}
	if h.LastBlockHash != prevHash {
		return bad("parent hash %q != %q", h.LastBlockHash, prevHash)
	}
	if h.TimeStart != prev.TimeEnd+1 || h.TimeEnd <= h.TimeStart || h.TimeEnd%consensus.SecondsPerBlock != 0 ||
		int64(h.TimeTotal) != h.TimeEnd-h.TimeStart {
		return bad("time slot")
	}
	if h.TimeEnd > n.UTCTime()+5 {
		return bad("block from the future")
	}
	if !b.V2 || len(b.Keys) != len(b.Orders) {
		return bad("block has no authentication trailer")
	}
	idx, err := n.checkSeal(b)
	if err != nil {
		return err
	}
	// FIX: the slot belongs to its turn holder for a while. A block of another
	// proposer for a slot is refused until OutOfTurnGrace seconds after the
	// slot's boundary: sealed a few seconds early it used to take the slot
	// (the turn holder, building at the boundary, found the tip already at that
	// time and could not build), and with it every reward and the choice of
	// orders. Once the grace has passed, a missed slot can still be filled and
	// the turn holder's own block, if it turns up, outweighs the stand-in.
	if props := n.Proposers(); len(props) > 0 && int(SlotOf(h.TimeEnd)%int64(len(props))) != idx &&
		n.UTCTime() < h.TimeEnd+OutOfTurnGrace {
		return bad("block of another proposer's slot, before the grace period of %d s", OutOfTurnGrace)
	}
	if miner := crypto.GetAddressFromPublicKey(b.SealKey, 0); h.AccountMiner != miner {
		return bad("miner %q is not the proposer %q", h.AccountMiner, miner)
	}
	if h.Reward != consensus.GetBlockReward(h.Number) {
		return bad("reward %d", h.Reward)
	}
	if int(h.TrxTotales) != len(b.Orders) {
		return bad("order count")
	}
	// FIX(re2 3, 1): every header field is a function of the chain except the
	// time slot, the miner and the orders. Nothing is left to grind, and the
	// state root and the proposer list digest are committed.
	if _, digest, ok := parseSolution(h.Solution); !ok || digest != n.chainDigest() {
		return bad("solution field is not the state commitment of this chain")
	}
	if h.TargetHash != codec.Truncate(prevHash, 32) || h.Difficult != 0 || h.TimeLast20 != 0 {
		return bad("header fields that must be fixed are not")
	}
	var wantNxt int32
	if h.Number >= 53000 {
		wantNxt = int32(len(b.MNsAddrs))
	}
	if h.NxtBlkDiff != wantNxt {
		return bad("next difficulty field")
	}
	if len(b.PosAddrs) != 0 || b.PosPay != 0 {
		return bad("proof-of-stake payments")
	}
	user := b.Orders
	var want types.Order
	hasDev := h.Number >= consensus.PoSBlockEnd
	if hasDev {
		if len(user) == 0 || user[len(user)-1].OrderType != "PROJCT" {
			return bad("project payment missing")
		}
		want = user[len(user)-1]
		user = user[:len(user)-1]
	}
	seen := map[string]bool{}
	var fees int64
	var transfers, gvts, psos int
	for i, o := range user {
		if int64(o.Block) != h.Number {
			return bad("order %d block field", i)
		}
		if o.Sender != o.Address {
			return bad("order %d sender is not its address", i)
		}
		if seen[o.TrfrID] || recent[o.TrfrID] {
			return bad("order %d repeated id", i)
		}
		seen[o.TrfrID] = true
		pool := o
		pool.Sender = b.Keys[i]
		if err := n.checkOrder(pool, prev, h.TimeEnd); err != nil {
			return bad("order %d: %v", i, err)
		}
		if b.Keys[i] == "" {
			return bad("order %d has no key", i)
		}
		switch o.OrderType {
		case "SNDGVT":
			gvts++
		case PSONew, PSOClear:
			psos++
		default:
			transfers++
		}
		var ok bool
		if fees, ok = consensus.CheckedAdd(fees, o.AmmountFee); !ok {
			return bad("fee total out of range")
		}
	}
	if err := checkOrderGroups(user); err != nil {
		return err
	}
	if transfers > consensus.MaxTransfersPerBlock || gvts > consensus.MaxGVTPerBlock || psos > consensus.MaxPSOPerBlock {
		return bad("too many orders (%d transfers, %d gvt, %d pso)", transfers, gvts, psos)
	}
	if hasDev && b.Keys[len(b.Keys)-1] != "" {
		return bad("project payment carries a key")
	}
	if h.MinerFee != fees {
		return bad("miner fee %d != sum of fees %d", h.MinerFee, fees)
	}
	if h.Number < consensus.MNBlockStart {
		if len(b.MNsAddrs) != 0 || b.MNsPay != 0 {
			return bad("masternode payments before block %d", consensus.MNBlockStart)
		}
	} else if len(b.MNsAddrs) > consensus.MaxMasternodesPerBlock {
		return bad("masternode list too long")
	}
	// FIX(C-03): the share is derived with checked arithmetic and must match
	// exactly; the original test `len*pay > share` wrapped around.
	dev, mnsPay, _, _, ok := consensus.Shares(h.Number, h.Reward, fees, len(b.MNsAddrs))
	if !ok {
		return bad("amounts out of range")
	}
	if b.MNsPay != mnsPay {
		return bad("masternode pay %d, expected %d", b.MNsPay, mnsPay)
	}
	if hasDev {
		if exp := createDevPaymentOrder(h.Number, h.TimeEnd, dev, prev.Number); !bytes.Equal(want.Encode(), exp.Encode()) {
			return bad("project payment is not the derived one")
		}
	}
	for _, a := range b.MNsAddrs {
		if !crypto.IsValidHashAddress(a) {
			return bad("masternode address %q", a)
		}
	}
	return nil
}

// checkOrderGroups binds OrderID to the lines of a wire order. The signature
// of every line covers its number (TrxLine) and the line count (OrderLines);
// OrderID is derived from the lines and cannot be signed (it contains the
// signatures' ids), so it is checked here. FIX(re2 H-2, 10; final round):
// lines that share an OrderID are one wire order and must pay one receiver at
// one time; the group must be complete, numbered 1..n in order, every line
// must declare n, and the id must be the one derived from the lines. A
// proposer can therefore not attach a line to someone else's order, execute a
// prefix of an order as a shorter one, or make one order pay two receivers.
func checkOrderGroups(user []types.Order) error {
	for i := 0; i < len(user); {
		g := user[i]
		n := int(g.OrderLines)
		if g.OrderType != "TRFR" {
			if n != 1 || g.TrxLine != 1 || g.OrderID != SingleOrderID(g.TrfrID) {
				return bad("order %d: id or line numbers do not match", i)
			}
			i++
			continue
		}
		if n < 1 || n > 30 || i+n > len(user) {
			return bad("order %d: %d lines declared", i, n)
		}
		ids := ""
		for j := 0; j < n; j++ {
			o := user[i+j]
			if o.OrderType != "TRFR" || o.OrderID != g.OrderID || int(o.OrderLines) != n || int(o.TrxLine) != j+1 ||
				o.Receiver != g.Receiver || o.TimeStamp != g.TimeStamp || o.Reference != g.Reference {
				return bad("order %d: lines of one order differ", i+j)
			}
			ids += o.TrfrID
		}
		if i+n < len(user) && user[i+n].OrderID == g.OrderID {
			return bad("order %d: more lines than declared", i)
		}
		derived := crypto.GetOrderHash(codec.IntToStr(int64(n)) + codec.IntToStr(g.TimeStamp) + ids)
		if g.OrderID != derived && (n != 1 || g.OrderID != SingleOrderID(g.TrfrID)) {
			return bad("order %d: id is not derived from its lines", i)
		}
		i += n
	}
	return nil
}
