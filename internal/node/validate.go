package node

import (
	"errors"
	"fmt"

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

// ValidateBlock checks a block received from a peer against its parent.
// FIX(C-03): the original stored whatever blocks a peer sent and relied on a
// 5-character vote (mpred.pas:666-686, masterpaskalform.pas:1098-1134). The
// checks: numbering and parent hash, time slots, reward arithmetic, fee
// totals, the shape of every order including the TrfrID derivation and the
// project payment, the masternode share, and the absence of duplicates.
// Signatures cannot be re-checked because blocks store the sender address in
// place of the public key.
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
	if h.Reward != consensus.GetBlockReward(h.Number) {
		return bad("reward %d", h.Reward)
	}
	if len(h.AccountMiner) == 0 || !crypto.IsValidHashAddress(h.AccountMiner) {
		return bad("miner address")
	}
	if len(b.Orders) > 2002 || int(h.TrxTotales) != len(b.Orders) {
		return bad("order count")
	}
	seen := map[string]bool{}
	var fees int64
	devSeen := false
	for i, o := range b.Orders {
		if int64(o.Block) != h.Number {
			return bad("order %d block field", i)
		}
		if o.AmmountTrf < 0 || o.AmmountFee < 0 {
			return bad("order %d negative amount", i)
		}
		if _, ok := consensus.CheckedAdd(o.AmmountTrf, o.AmmountFee); !ok {
			return bad("order %d amount range", i)
		}
		if seen[o.TrfrID] || recent[o.TrfrID] {
			return bad("order %d repeated id", i)
		}
		seen[o.TrfrID] = true
		switch o.OrderType {
		case "TRFR", "CUSTOM", "SNDGVT":
			if o.Sender != o.Address || o.TrfrID != OrderTrfrID(o, o.Address) {
				return bad("order %d id not derived from its fields", i)
			}
			fees += o.AmmountFee
			switch o.OrderType {
			case "TRFR":
				if !ValidReceiver(o.Receiver) {
					return bad("order %d receiver", i)
				}
			case "CUSTOM":
				if o.AmmountFee != consensus.GetCustFee(h.Number) || o.AmmountTrf != 0 || !ValidAlias(o.Receiver) {
					return bad("order %d custom", i)
				}
			case "SNDGVT":
				if o.AmmountFee != consensus.GetCustFee(h.Number) || o.AmmountTrf != 0 || !ValidReceiver(o.Receiver) {
					return bad("order %d gvt", i)
				}
			}
		case "PROJCT":
			if devSeen || o.Sender != "COINBASE" || o.Address != "COINBASE" || o.Receiver != consensus.ProjectFunds ||
				h.Number < consensus.PoSBlockEnd {
				return bad("order %d project payment", i)
			}
			devSeen = true
		default:
			return bad("order %d type %q", i, o.OrderType)
		}
	}
	if h.MinerFee != fees {
		return bad("miner fee %d != sum of fees %d", h.MinerFee, fees)
	}
	if h.Number >= consensus.PoSBlockEnd {
		want := (h.Reward + fees) * consensus.GetDevPercentage(h.Number) / 10000
		var got int64 = -1
		for _, o := range b.Orders {
			if o.OrderType == "PROJCT" {
				got = o.AmmountTrf
			}
		}
		if got != want {
			return bad("project payment %d != %d", got, want)
		}
	}
	if len(b.PosAddrs) != 0 {
		return bad("proof-of-stake payments")
	}
	if h.Number >= consensus.MNBlockStart {
		share := (h.Reward + fees) * consensus.GetMNsPercentage(h.Number, n.CFG.Param(0)) / 10000
		if b.MNsPay < 0 || int64(len(b.MNsAddrs))*b.MNsPay > share {
			return bad("masternode share")
		}
		for _, a := range b.MNsAddrs {
			if !crypto.IsValidHashAddress(a) {
				return bad("masternode address %q", a)
			}
		}
	}
	return nil
}
