package node

import (
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// OrderFields lists every signed field of an order in a fixed order.
// FIX(C-04, H-07): the original signed only timestamp+origin+receiver+
// amount+fee+line (mpprotocol.pas:792) and left the type, the reference and
// the TrfrID outside the signature.
func OrderFields(o types.Order, origin string) []string {
	return []string{o.OrderType, codec.IntToStr(o.TimeStamp), origin, o.Receiver,
		codec.IntToStr(o.AmmountTrf), codec.IntToStr(o.AmmountFee), codec.IntToStr(int64(o.TrxLine)), o.Reference}
}

// OrderTrfrID derives the transfer id from all signed fields. FIX(C-04): in
// the original it was a hash of a few fields chosen by the sender
// (mpcoin.pas:300) and never recomputed by receivers, so it could be changed
// without invalidating the signature, and the same signed transfer could be
// replayed under new ids.
func OrderTrfrID(o types.Order, origin string) string {
	return crypto.GetTransferHash(string(crypto.Canonical("TRFRID1", OrderFields(o, origin)...)))
}

// SingleOrderID is the id of CUSTOM and SNDGVT orders.
func SingleOrderID(trfrID string) string { return crypto.GetOrderHash("1" + trfrID) }

// SignOrder fills Signature and TrfrID of an order whose other fields are set.
func SignOrder(o *types.Order, priv string) {
	o.Signature = crypto.SignCanonical(priv, "ORDER1", OrderFields(*o, o.Address)...)
	o.TrfrID = OrderTrfrID(*o, o.Address)
}

// VerifyOrder checks the signature, the key-address binding and the TrfrID.
// It returns a non-zero code on failure: 6 bad signature, 13 TrfrID not
// derived from the signed fields, 14 key does not belong to the address.
func VerifyOrder(o types.Order) int {
	if crypto.GetAddressFromPublicKey(o.Sender, 0) != o.Address {
		return 14
	}
	if o.TrfrID != OrderTrfrID(o, o.Address) {
		return 13
	}
	// A signature is checked once: pool admission and block validation ask
	// about the same order, and an ECDSA verification costs milliseconds.
	key := crypto.SHA256String(o.Sender + "|" + o.Signature + "|" + o.TrfrID)
	if verified.has(key) {
		return 0
	}
	if !crypto.VerifyCanonical(o.Sender, o.Signature, "ORDER1", OrderFields(o, o.Address)...) {
		return 6
	}
	verified.add(key)
	return 0
}

// verified remembers orders whose signature checked out. The key covers the
// public key, the signature and the TrfrID, which is derived from every
// signed field, so a changed order is a cache miss.
var verified = &sigCache{m: map[string]struct{}{}}

type sigCache struct {
	mu sync.Mutex
	m  map[string]struct{}
}

func (c *sigCache) has(k string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.m[k]
	return ok
}

func (c *sigCache) add(k string) {
	c.mu.Lock()
	if len(c.m) >= 1<<14 {
		c.m = map[string]struct{}{}
	}
	c.m[k] = struct{}{}
	c.mu.Unlock()
}

// ValidAlias applies the alias rules of CustomizeAddress (mpparser.pas:
// 600-660) on the receiving side. FIX(M-01): the original enforced them only
// in the sender's own client.
func ValidAlias(a string) bool {
	if len(a) < 5 || len(a) > 40 || crypto.IsValidHashAddress(a) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@*+-_:", rune(a[i])) {
			return false
		}
	}
	return true
}

// ValidReceiver reports whether funds may be sent to addr. FIX(L-01, L-08):
// multi-signature "M" addresses have no spending rule and the sum checksum
// cannot detect swapped characters, so only regular, well-formed addresses of
// at most 40 characters are accepted as targets of new transfers.
func ValidReceiver(addr string) bool {
	return len(addr) <= 40 && len(addr) > 20 && addr[0] == 'N' && crypto.IsValidHashAddress(addr)
}

// SendFundsFromAddress mirrors mpcoin.pas:272-303 with the signed encoding
// of OrderFields.
func (n *Node) SendFundsFromAddress(origen, destino string, monto, comision int64, reference, orderTime string, line int) (types.Order, error) {
	idx := n.Wallet.IndexOf(origen)
	w := n.Wallet.At(idx)
	available := n.Summary.BalanceIndexed(w.Hash) - n.AddressPendingPays(origen)
	var fee, trf int64
	if available > comision {
		fee = comision
	} else {
		fee = available
	}
	if available > monto+comision {
		trf = monto
	} else {
		trf = available - comision
	}
	if trf < 0 {
		trf = 0
	}
	ts, ok := codec.StrToInt64(orderTime)
	if !ok {
		return types.Order{}, errBadTime
	}
	o := types.Order{
		OrderLines: 1, OrderType: "TRFR", TimeStamp: ts, Reference: reference,
		TrxLine: int32(line), Sender: w.PublicKey, Address: w.Hash, Receiver: destino,
		AmmountFee: fee, AmmountTrf: trf,
	}
	SignOrder(&o, w.PrivateKey)
	o.Normalize()
	return o, nil
}

type nodeError string

func (e nodeError) Error() string { return string(e) }

const errBadTime = nodeError("invalid order time")

var _ = consensus.MaxSupply
