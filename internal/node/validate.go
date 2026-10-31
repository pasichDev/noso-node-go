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
func checkOrder(o types.Order, prev types.BlockHeader, blockTime int64) error {
	switch o.OrderType {
	case "TRFR", "CUSTOM", "SNDGVT":
	default:
		return fmt.Errorf("order type %q", o.OrderType)
	}
	if o.AmmountTrf < 0 || o.AmmountFee < 0 {
		return errors.New("negative amount")
	}
	if _, ok := consensus.CheckedAdd(o.AmmountTrf, o.AmmountFee); !ok {
		return errors.New("amount range")
	}
	if o.TimeStamp < prev.TimeStart || o.TimeStamp+60 > blockTime {
		return errors.New("order time outside the block window")
	}
	if o.Sender == "" || len(o.Sender) > 120 {
		return errors.New("missing public key")
	}
	if c := VerifyOrder(o); c != 0 {
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
	if _, err := n.checkSeal(b); err != nil {
		return err
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
	var transfers, gvts int
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
		if err := checkOrder(pool, prev, h.TimeEnd); err != nil {
			return bad("order %d: %v", i, err)
		}
		if b.Keys[i] == "" {
			return bad("order %d has no key", i)
		}
		if o.OrderType == "SNDGVT" {
			gvts++
		} else {
			transfers++
		}
		var ok bool
		if fees, ok = consensus.CheckedAdd(fees, o.AmmountFee); !ok {
			return bad("fee total out of range")
		}
	}
	if transfers > consensus.MaxTransfersPerBlock || gvts > consensus.MaxGVTPerBlock {
		return bad("too many orders (%d transfers, %d gvt)", transfers, gvts)
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

var _ = codec.IntToStr
