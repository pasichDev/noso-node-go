package types

import (
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// StringFromOrder mirrors GetStringFromOrder (nosogeneral.pas:609-625).
// COMPAT: the first token is the OrderType, not a command word; the second
// copy of OrderType sits at its normal position (field order preserved).
func StringFromOrder(o Order) string {
	return strings.Join([]string{
		o.OrderType, o.OrderID, codec.IntToStr(int64(o.OrderLines)), o.OrderType,
		codec.IntToStr(o.TimeStamp), o.Reference, codec.IntToStr(int64(o.TrxLine)),
		o.Sender, o.Address, o.Receiver, codec.IntToStr(o.AmmountFee),
		codec.IntToStr(o.AmmountTrf), o.Signature, o.TrfrID,
	}, " ")
}

// ParseOrder mirrors GetOrderFromString (mpprotocol.pas:93-121). Fields are
// taken by position 1..13 (position 0 is the command token); StrToInt
// failures make the whole parse fail while leaving the already assigned
// fields in place, as in Pascal.
func ParseOrder(line string) (Order, bool) {
	var o Order
	p := func(n int64) string { return codec.Parameter(line, n) }
	o.OrderID = p(1)
	v, ok := codec.StrToInt(p(2))
	if !ok {
		o.Normalize()
		return o, false
	}
	o.OrderLines = v
	o.OrderType = p(3)
	t, ok := codec.StrToInt64(p(4))
	if !ok {
		o.Normalize()
		return o, false
	}
	o.TimeStamp = t
	o.Reference = p(5)
	v, ok = codec.StrToInt(p(6))
	if !ok {
		o.Normalize()
		return o, false
	}
	o.TrxLine = v
	o.Sender, o.Address, o.Receiver = p(7), p(8), p(9)
	if tooLong(o) {
		return o, false
	}
	if o.AmmountFee, ok = codec.StrToInt64(p(10)); !ok {
		o.Normalize()
		return o, false
	}
	if o.AmmountTrf, ok = codec.StrToInt64(p(11)); !ok {
		o.Normalize()
		return o, false
	}
	o.Signature, o.TrfrID = p(12), p(13)
	if tooLong(o) {
		return o, false
	}
	o.Normalize()
	return o, true
}

// StringFromHeader mirrors GetStringFromBlockHeader (mpprotocol.pas:145-161).
func StringFromHeader(h BlockHeader) string {
	i := func(v int64) string { return codec.IntToStr(v) }
	return "Number:" + i(h.Number) + " Start:" + i(h.TimeStart) + " End:" + i(h.TimeEnd) +
		" Total:" + i(int64(h.TimeTotal)) + " 20:" + i(int64(h.TimeLast20)) +
		" Trxs:" + i(int64(h.TrxTotales)) + " Diff:" + i(int64(h.Difficult)) +
		" Target:" + h.TargetHash + " Solution:" + h.Solution +
		" NextDiff:" + i(int64(h.NxtBlkDiff)) + " Miner:" + h.AccountMiner +
		" Fee:" + i(h.MinerFee) + " Reward:" + i(h.Reward)
}

// tooLong reports whether a parsed field exceeds its ShortString capacity.
// FIX(L-08): the original silently truncated (nosogeneral.pas:26-41), so two
// different addresses could collapse into one 40 character account.
func tooLong(o Order) bool {
	return len(o.OrderID) > 64 || len(o.OrderType) > 6 || len(o.Reference) > 64 || len(o.Sender) > 120 ||
		len(o.Address) > 40 || len(o.Receiver) > 40 || len(o.Signature) > 120 || len(o.TrfrID) > 64
}

// ValidReference reports whether s may be the Reference of a new order. FIX(re2
// H-2): the field is copied into text that is split again on '$', ' ', ':',
// '(' , ')' and 0x7f (wire lines, NSLBLKORD, the RPC objects), so a byte of
// those lets a sender write the next record. Only a plain printable set is
// accepted: letters, digits and _ - . , @ + * = # / ! ? % & [ ] { } ~ ^ | < >.
// At most 64 bytes, not empty.
func ValidReference(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c < 0x80 && strings.IndexByte("_-.,@+*=#/!?%&[]{}~^|<>", c) >= 0:
		default:
			return false
		}
	}
	return true
}
