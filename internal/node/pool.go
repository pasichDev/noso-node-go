package node

import (
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// PendingCount mirrors GetPendingCount.
func (n *Node) PendingCount() int {
	n.poolMu.Lock()
	defer n.poolMu.Unlock()
	return len(n.pool)
}

// ClearPending mirrors ClearAllPending.
func (n *Node) ClearPending() {
	n.poolMu.Lock()
	n.pool = nil
	n.poolMu.Unlock()
}

// PendingCopy returns a snapshot of the pool.
func (n *Node) PendingCopy() []types.Order {
	n.poolMu.Lock()
	defer n.poolMu.Unlock()
	return append([]types.Order(nil), n.pool...)
}

// SetPending replaces the pool (used after a block keeps ignored orders).
func (n *Node) SetPending(o []types.Order) {
	n.poolMu.Lock()
	n.pool = append([]types.Order(nil), o...)
	n.poolMu.Unlock()
}

// TruncatePending mirrors the `setlength(ArrayPoolTXs,0)` of
// VerifyConnectionStatus (mpred.pas:519-522) when the network reports
// fewer pending orders than we hold.
func (n *Node) TruncatePending() { n.ClearPending() }

// TranxAlreadyPending mirrors nosonetwork.pas:260-278.
func (n *Node) TranxAlreadyPending(trfrID string) bool {
	n.poolMu.Lock()
	defer n.poolMu.Unlock()
	for _, o := range n.pool {
		if o.TrfrID == trfrID {
			return true
		}
	}
	return false
}

// TrxExistsInLastBlock mirrors nosonetwork.pas:332-348.
func (n *Node) TrxExistsInLastBlock(trfrID string) bool {
	for _, o := range n.Blocks.Orders(n.MyLastBlock()) {
		if o.TrfrID == trfrID {
			return true
		}
	}
	return false
}

// AddPool mirrors AddArrayPoolTXs (nosonetwork.pas:281-329): orders older
// than the last block, already mined, or (late in the period) too old are
// dropped; the rest are inserted ordered by timestamp, then OrderID, then
// TrxLine.
func (n *Node) AddPool(o types.Order) bool {
	last := n.LastBlockData()
	if o.TimeStamp < last.TimeStart {
		return false
	}
	if n.TrxExistsInLastBlock(o.TrfrID) {
		return false
	}
	if n.BlockAge() > 585 && o.TimeStamp < last.TimeStart+540 {
		return false
	}
	if n.TranxAlreadyPending(o.TrfrID) {
		return false
	}
	n.poolMu.Lock()
	defer n.poolMu.Unlock()
	pos := len(n.pool)
	for i, p := range n.pool {
		if o.TimeStamp < p.TimeStamp {
			pos = i
			break
		} else if o.TimeStamp == p.TimeStamp {
			if o.OrderID < p.OrderID {
				pos = i
				break
			} else if o.OrderID == p.OrderID && o.TrxLine < p.TrxLine {
				pos = i
				break
			}
		}
	}
	n.pool = append(n.pool, types.Order{})
	copy(n.pool[pos+1:], n.pool[pos:])
	n.pool[pos] = o
	return true
}

// AddressPendingPays mirrors GetAddressPendingPays (mpcoin.pas:47-68): what
// the address has already committed in the pool, plus 1050000 NOSO while
// the address is a locked masternode (after block 120000).
func (n *Node) AddressPendingPays(addr string) int64 {
	if addr == "" {
		return 0
	}
	var r int64
	for _, o := range n.PendingCopy() {
		if o.Address == addr {
			r += o.AmmountFee + o.AmmountTrf
		}
	}
	if n.MyLastBlock() >= consensus.Update050Block && n.PSOs.IsLocked(addr) {
		r += 1050000000000
	}
	return r
}

// AddressAvailable mirrors GetAddressAvailable.
func (n *Node) AddressAvailable(addr string) int64 {
	return n.Summary.BalanceIndexed(addr) - n.AddressPendingPays(addr)
}

// AddressIncomingPays mirrors GetAddressIncomingpays.
func (n *Node) AddressIncomingPays(addr string) int64 {
	var r int64
	for _, o := range n.PendingCopy() {
		if o.Receiver == addr {
			r += o.AmmountTrf
		}
	}
	return r
}

// AddressAlreadyCustomized mirrors mpcoin.pas:218-227.
func (n *Node) AddressAlreadyCustomized(addr string) bool {
	if n.Summary.Alias(addr) != "" {
		return true
	}
	for _, o := range n.PendingCopy() {
		if o.Address == addr && o.OrderType == "CUSTOM" {
			return true
		}
	}
	return false
}

// AliasAlreadyExists mirrors mpcoin.pas:252-262.
func (n *Node) AliasAlreadyExists(alias string) bool {
	if slot, _ := n.Summary.GetIndexPosition(alias, true); slot >= 0 {
		return true
	}
	for _, o := range n.PendingCopy() {
		if o.OrderType == "CUSTOM" && o.Receiver == alias {
			return true
		}
	}
	return false
}

// GVTAlreadyTransferred mirrors mpcoin.pas:229-249.
func (n *Node) GVTAlreadyTransferred(num string) bool {
	if codec.StrToIntDef(num, -1) < 0 {
		return true
	}
	for _, o := range n.PendingCopy() {
		if o.Reference == num && o.OrderType == "SNDGVT" {
			return true
		}
	}
	return false
}

// IsAddressLocked mirrors mpprotocol.pas:772-777 (substring test on the
// frozen-addresses CFG field).
func (n *Node) IsAddressLocked(addr string) bool {
	return strings.Contains(n.CFG.Param(5), addr)
}

// TrxSeenRecently reports whether an order id appears in the last three
// blocks. FIX(C-04): the original looked only at the last block
// (nosonetwork.pas:332-348).
func (n *Node) TrxSeenRecently(trfrID string) bool {
	last := n.MyLastBlock()
	for b := last; b > last-3 && b >= 0; b-- {
		for _, o := range n.Blocks.Orders(b) {
			if o.TrfrID == trfrID {
				return true
			}
		}
	}
	return false
}

// ValidateTrfr mirrors mpprotocol.pas:779-811; the first failing check
// returns its code. FIX(C-04, C-05, H-07, L-01): amounts are range and
// overflow checked, the signature covers every field, the TrfrID must be
// derived from the signed data and be unseen, and the receiver must be a
// regular address.
func (n *Node) ValidateTrfr(o types.Order, origen string) int {
	last := n.LastBlockData()
	total, sumOK := consensus.CheckedAdd(o.AmmountFee, o.AmmountTrf)
	switch {
	case o.AmmountTrf < 0:
		return 7
	case o.AmmountFee < 0:
		return 8
	case !sumOK:
		return 15
	case o.OrderType != "TRFR":
		return 16
	case n.Summary.BalanceIndexed(origen)-n.AddressPendingPays(origen) < total:
		return 1
	case n.TranxAlreadyPending(o.TrfrID):
		return 2
	case o.TimeStamp < last.TimeStart:
		return 3
	case o.TimeStamp > last.TimeEnd+600:
		return 4
	case n.TrxSeenRecently(o.TrfrID):
		return 5
	case !crypto.IsValidHashAddress(origen):
		return 9
	case !ValidReceiver(o.Receiver):
		return 10
	case n.IsAddressLocked(o.Address):
		return 11
	case strings.Contains(n.CFG.Param(0), "EMPTY") || strings.Contains(n.CFG.Param(0), "STOP"):
		return 12
	case origen != o.Address:
		return 13
	}
	return VerifyOrder(o)
}

// PTCOrder mirrors PTC_Order (mpprotocol.pas:842-948). It returns the new
// order id on success, "ERROR n" for a rejected order, or "" when the line
// could not even be parsed.
//
// FIX(L-03): the first error code is kept (the original let the validation
// loop overwrite codes 96-99 with 0, so a rejected order could be answered
// with an empty string, mpprotocol.pas:917-927) and validation only runs on
// a completely parsed line.
func (n *Node) PTCOrder(line string) string {
	num, ok := codec.StrToInt(codec.Parameter(line, 5))
	if !ok {
		return ""
	}
	numTransfers := int(num)
	n.logf("events", "Order with "+codec.IntToStr(int64(numTransfers))+" transfers")
	recOrderID := codec.Parameter(line, 7)
	genOrderID := codec.Parameter(line, 5) + codec.Parameter(line, 10)
	textbak := codec.GetOpData(line)
	proceder := true
	errorCode := -1
	setCode := func(c int) {
		if errorCode <= 0 {
			errorCode = c
		}
	}
	var totalSent, totalFee int64
	if numTransfers > 30 {
		proceder = false
		setCode(89)
	}
	var trx []types.Order
	var senders []string
	sendersString := ""
	for cont := 0; cont < numTransfers; cont++ {
		if !proceder {
			break
		}
		o, ok := types.ParseOrder(textbak)
		trx = append(trx, o)
		senders = append(senders, "")
		if !ok {
			proceder = false
			setCode(96)
		}
		totalSent += o.AmmountTrf
		totalFee += o.AmmountFee
		genOrderID += o.TrfrID
		if n.TranxAlreadyPending(o.TrfrID) {
			proceder = false
			setCode(98)
		}
		senders[cont] = crypto.GetAddressFromPublicKey(o.Sender, 0)
		if senders[cont] != o.Address {
			proceder = false
			setCode(97)
		}
		if strings.Contains(sendersString, senders[cont]) {
			proceder = false
			setCode(99)
		}
		sendersString += senders[cont]
		if len(textbak) >= 1 {
			textbak = textbak[1:]
		}
		textbak = codec.GetOpData(textbak)
	}
	genOrderID = crypto.GetOrderHash(genOrderID)
	todoValido := true
	if totalFee < consensus.GetMinimumFee(totalSent) {
		todoValido = false
		setCode(100)
	}
	if recOrderID != genOrderID {
		todoValido = false
		setCode(101)
	}
	if todoValido && proceder {
		for cont := 0; cont < numTransfers && cont < len(trx); cont++ {
			if c := n.ValidateTrfr(trx[cont], senders[cont]); c > 0 {
				setCode(c)
				todoValido = false
				break
			}
		}
	}
	if !todoValido {
		proceder = false
	}
	if proceder {
		tb := PTCHeader(n) + "ORDER " + codec.IntToStr(int64(numTransfers)) + " " + codec.GetOpData(line)
		for _, o := range trx {
			n.AddPool(o)
		}
		if n.Broadcast != nil && n.serverActive() {
			n.Broadcast(tb)
		}
		return codec.Parameter(tb, 7)
	}
	if errorCode > 0 {
		return "ERROR " + codec.IntToStr(int64(errorCode))
	}
	return ""
}

func (n *Node) serverActive() bool { return n.ServerOn != nil && n.ServerOn() }

// PTCHeader mirrors GetPTCEcn (nosonetwork.pas:374-377).
func PTCHeader(n *Node) string {
	return "PSK " + codec.IntToStr(Protocol) + " " + MainnetVersion + NodeRelease + " " + n.UTCTimeStr() + " "
}

// PTCCustom mirrors PTC_Custom (mpprotocol.pas:744-770). FIX(C-06, M-01,
// L-03): the fee must equal the exact custom fee and no amount may move, the
// alias rules are enforced here, the ids are derived from the signed data
// and an unparsable order is an error (the original answered 0, success).
func (n *Node) PTCCustom(line string) int {
	o, ok := types.ParseOrder(line)
	if !ok {
		return 17
	}
	addr := crypto.GetAddressFromPublicKey(o.Sender, 0)
	code := 0
	if o.OrderType != "CUSTOM" {
		code = 16
	}
	if addr != o.Address {
		code = 1
	}
	if o.AmmountFee != consensus.GetCustFee(n.MyLastBlock()) || o.AmmountTrf != 0 {
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
	if n.AddressAlreadyCustomized(addr) {
		code = 6
	}
	if !ValidAlias(o.Receiver) {
		code = 11
	}
	if n.AliasAlreadyExists(o.Receiver) {
		code = 7
	}
	if o.OrderID != SingleOrderID(o.TrfrID) {
		code = 12
	}
	if c := VerifyOrder(o); c != 0 {
		code = c
	}
	if code == 0 {
		op := codec.GetOpData(line)
		n.AddPool(o)
		if n.Broadcast != nil && n.serverActive() {
			n.Broadcast(PTCHeader(n) + op)
		}
	}
	return code
}

// PTCSendGVT mirrors PTC_SendGVT (mpprotocol.pas:956-985). FIX(M-14, L-03):
// the OWNER of the GVT authorises the transfer with their own key (the
// original demanded the developer key, which froze every owner's GVT).
func (n *Node) PTCSendGVT(line string) int {
	o, ok := types.ParseOrder(line)
	if !ok {
		return 17
	}
	addr := crypto.GetAddressFromPublicKey(o.Sender, 0)
	code := 0
	if o.OrderType != "SNDGVT" {
		code = 16
	}
	if addr != o.Address {
		code = 1
	}
	if o.AmmountFee != consensus.GetCustFee(n.MyLastBlock()) || o.AmmountTrf != 0 {
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
	if n.GVTAlreadyTransferred(o.Reference) {
		code = 6
	}
	num := codec.StrToIntDef(o.Reference, -1)
	if num < 0 || num > 99 || n.GVTs.Index(int(num)).Owner != addr {
		code = 8
	}
	if !ValidReceiver(o.Receiver) {
		code = 10
	}
	if o.OrderID != SingleOrderID(o.TrfrID) {
		code = 12
	}
	if c := VerifyOrder(o); c != 0 {
		code = c
	}
	if code == 0 {
		op := codec.GetOpData(line)
		n.AddPool(o)
		if n.Broadcast != nil && n.serverActive() {
			n.Broadcast(PTCHeader(n) + op)
		}
	}
	if code > 0 {
		n.logf("events", "SendGVT error: "+codec.IntToStr(int64(code)))
	}
	return code
}
