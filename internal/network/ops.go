package network

import (
	"fmt"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// CustomValid is masterpaskalform.pas:565: characters allowed in an alias.
const CustomValid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@*+-_:"

// Printer receives console output lines.
type Printer func(string)

func (p Printer) say(format string, a ...any) {
	if p != nil {
		p(fmt.Sprintf(format, a...))
	}
}

// WalletBalance mirrors GetWalletBalance (mpparser.pas:~395): the sum of the
// summary balances of every wallet address minus our outgoing pendings.
func (e *Engine) WalletBalance() int64 {
	var total int64
	for _, w := range e.N.Wallet.All() {
		total += e.N.Summary.BalanceIndexed(w.Hash)
	}
	return total - e.N.MontoOutgoing
}

// SendFunds mirrors SendFunds (mpparser.pas:~720-835). line is
// "sendto {destination} {amount} {reference}". startIdx is the first wallet
// address tried (the GUI passes the selected row; the console uses 0).
// COMPAT: the order text is rewritten to start with NSLORDER, handed to a
// peer and ALSO broadcast with that prefix.
func (e *Engine) SendFunds(line string, say Printer, startIdx int) string {
	n := e.N
	dest, amount, reference := codec.Parameter(line, 1), codec.Parameter(line, 2), codec.Parameter(line, 3)
	ok := true
	if dest == "" || amount == "" {
		say.say("Invalid parameters.")
		ok = false
	}
	if !crypto.IsValidHashAddress(dest) {
		slot, rec := n.Summary.GetIndexPosition(dest, true)
		if slot < 0 {
			say.say("Invalid destination.")
			ok = false
		} else {
			dest = rec.Hash
		}
	}
	if ok && !node.ValidReceiver(dest) { // FIX(L-01, L-08)
		say.say("Invalid destination.")
		ok = false
	}
	monto := codec.StrToInt64Def(amount, -1)
	if reference == "" {
		reference = "null"
	}
	if monto <= 10 || monto > consensus.MaxSupply { // FIX(C-05)
		say.say("Invalid ammount.")
		ok = false
	}
	var comision, montoShow, comisionShow int64
	if ok {
		comision = consensus.GetMinimumFee(monto)
		montoShow, comisionShow = monto, comision
		restante := monto + comision
		var coins int64
		if n.Options().MultiSend {
			h := n.Wallet.At(startIdx).Hash // FIX(G3): the funds start at the selected address
			coins = n.Summary.BalanceIndexed(h) - n.AddressPendingPays(h)
		} else {
			coins = e.WalletBalance()
		}
		if restante > coins {
			say.say("Insufficient funds. Needed: %s", Int2Curr(monto+comision))
			ok = false
		}
	}
	if !ok {
		say.say("Syntax: sendto {destination} {ammount} {reference}")
		return ""
	}
	cur := n.UTCTimeStr()
	var trfrs []types.Order
	idx := startIdx
	orderHashString := cur
	senders := ""
	line_ := 0
	for monto > 0 {
		w := n.Wallet.At(idx)
		if strings.Contains(senders, w.Hash) {
			say.say("Duplicated address on order")
			return ""
		}
		senders += w.Hash
		if n.Summary.BalanceIndexed(w.Hash)-n.AddressPendingPays(w.Hash) > 0 {
			line_++
			o, err := n.SendFundsFromAddress(w.Hash, dest, monto, comision, reference, cur, line_)
			if err != nil {
				return ""
			}
			trfrs = append(trfrs, o)
			comision -= o.AmmountFee
			monto -= o.AmmountTrf
			orderHashString += o.TrfrID
		}
		idx++
		if idx >= n.Wallet.Len() {
			idx = 0
		}
	}
	orderID := crypto.GetOrderHash(codec.IntToStr(int64(line_)) + orderHashString)
	for i := range trfrs {
		trfrs[i].OrderID = orderID
		trfrs[i].OrderLines = int32(line_)
	}
	os := node.PTCHeader(n) + "ORDER " + codec.IntToStr(int64(line_)) + " $"
	for _, o := range trfrs {
		os += types.StringFromOrder(o) + " $"
	}
	os = os[:len(os)-2]
	os = strings.Replace(os, "PSK", "NSLORDER", 1)
	say.say("Send to Node %s", os)
	res := e.SendOrderToNode(os)
	if strings.HasPrefix(res, "ERROR") {
		// FIX(M2): the order was not accepted by any node; it is neither
		// announced as sent nor broadcast, and the caller sees the error.
		say.say("The order was NOT sent: %s (%s)", res, sendErrorText(res))
		return res
	}
	e.OutgoingAdd(os)
	say.say("Send to: %s\nSend %s fee %s\nOrder ID: %s", dest, Int2Curr(montoShow), Int2Curr(comisionShow), orderID)
	return res
}

// SendGVT mirrors SendGVT (mpparser.pas:~870-935).
func (e *Engine) SendGVT(line string, say Printer) string {
	n := e.N
	num := int(codec.StrToIntDef(codec.Parameter(line, 1), -1))
	dest := codec.Parameter(line, 2)
	if num < 0 || num > n.GVTs.Len()-1 {
		say.say("Invalid GVT number")
		return ""
	}
	g := n.GVTs.Index(num)
	if n.Wallet.IndexOf(g.Owner) < 0 {
		say.say("You do not own that GVT")
		return ""
	}
	if n.AddressAvailable(g.Owner) < consensus.GetCustFee(n.MyLastBlock()) {
		say.say("Inssuficient funds")
		return ""
	}
	if !crypto.IsValidHashAddress(dest) {
		slot, rec := n.Summary.GetIndexPosition(dest, true)
		if slot < 0 {
			say.say("Invalid destination.")
			return ""
		}
		dest = rec.Hash
	}
	if g.Owner == dest {
		say.say("Can not transfer GVT to same address")
		return ""
	}
	w := n.Wallet.At(n.Wallet.IndexOf(g.Owner))
	ts, _ := codec.StrToInt64(n.UTCTimeStr())
	o := types.Order{OrderLines: 1, OrderType: "SNDGVT", TimeStamp: ts, Reference: g.Number, TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: dest, AmmountFee: consensus.GetCustFee(n.MyLastBlock())}
	node.SignOrder(&o, w.PrivateKey)
	o.OrderID = node.SingleOrderID(o.TrfrID)
	o.Normalize()
	e.OutgoingAdd(e.ProtocolLine(0) + "$" + types.StringFromOrder(o))
	say.say("GVT %s transfered from %s to %s\nOrder: %s", g.Number, w.Hash, dest, o.OrderID)
	return o.OrderID
}

// Customize mirrors CustomizeAddress (mpparser.pas:~640-720) combined with
// the crypto worker that signs and broadcasts the CUSTOM order.
func (e *Engine) Customize(line string, say Printer) bool {
	n := e.N
	addr, alias := codec.Parameter(line, 1), codec.Parameter(line, 2)
	ok := true
	idx := n.Wallet.IndexOf(addr)
	if idx < 0 {
		say.say("Invalid address")
		ok = false
	}
	w := n.Wallet.At(idx)
	if w.Custom != "" {
		say.say("Address already have a custom alias")
		ok = false
	}
	if len(alias) < 5 || len(alias) > 40 {
		say.say("Alias must have between 5 and 40 chars")
		ok = false
	}
	if crypto.IsValidHashAddress(alias) {
		say.say("Alias can not be a valid address")
		ok = false
	}
	if w.Balance < consensus.GetCustFee(n.MyLastBlock()) {
		say.say("Insufficient balance")
		ok = false
	}
	if n.AddressAlreadyCustomized(addr) {
		say.say("Address already have a custom alias")
		ok = false
	}
	if n.AliasAlreadyExists(alias) {
		say.say("Alias already exists")
		ok = false
	}
	for i := 0; i < len(alias); i++ {
		if !strings.ContainsRune(CustomValid, rune(alias[i])) {
			say.say("Invalid character in alias: %c", alias[i])
			ok = false
		}
	}
	if !ok || !node.ValidAlias(alias) {
		return false
	}
	ts, _ := codec.StrToInt64(n.UTCTimeStr())
	o := types.Order{OrderLines: 1, OrderType: "CUSTOM", TimeStamp: ts, Reference: "null", TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: alias, AmmountFee: consensus.GetCustFee(n.MyLastBlock())}
	node.SignOrder(&o, w.PrivateKey)
	o.OrderID = node.SingleOrderID(o.TrfrID)
	o.Normalize()
	e.OutgoingAdd(e.ProtocolLine(0) + "$" + types.StringFromOrder(o))
	say.say("Customization sent")
	return true
}

// NewAddress mirrors the crypto thread's address generation (tipo 1).
func (e *Engine) NewAddress() (types.Wallet, error) {
	return e.N.Wallet.NewAddress() // written through before it is returned
}

// OrderGroup is TOrderGroup (nosounit.pas:26-37).
type OrderGroup struct {
	Block      int32
	TimeStamp  int64
	OrderID    string
	OrderType  string
	OrderLines int32
	Reference  string
	Sender     string
	Receiver   string
	AmmountFee int64
	AmmountTrf int64
}

// OrderDetails mirrors GetOrderDetails (mpred.pas:849-931). COMPAT: orders
// already mined are only found through the blocks database index, which
// exists only when the BlocksDB option is enabled.
func (e *Engine) OrderDetails(orderID string) OrderGroup {
	n := e.N
	var r OrderGroup
	found := false
	// Lines of one order are merged only when id, type, receiver and time agree
	// (as getblockorders does): lines that merely share an id are separate
	// orders and are not summed into one.
	var key *types.Order
	add := func(o types.Order, block int32, sender string) {
		if key == nil {
			c := o
			key = &c
		} else if o.OrderID != key.OrderID || o.OrderType != key.OrderType || o.Receiver != key.Receiver ||
			o.TimeStamp != key.TimeStamp {
			return
		}
		r.OrderID, r.Block, r.Reference, r.TimeStamp, r.Receiver = o.OrderID, block, o.Reference, o.TimeStamp, o.Receiver
		if o.OrderLines == 1 {
			r.Sender = sender
		} else {
			r.Sender += fmt.Sprintf("[%s,%d,%d]", o.Address, o.AmmountTrf, o.AmmountFee)
		}
		r.AmmountTrf += o.AmmountTrf
		r.AmmountFee += o.AmmountFee
		r.OrderLines++
		r.OrderType = o.OrderType
		found = true
	}
	for _, o := range n.PendingCopy() {
		if o.OrderID == orderID {
			add(o, -1, o.Address)
		}
	}
	if found {
		return r
	}
	if b := n.DB.BlockFromOrder(n.Blocks, orderID); b >= 0 {
		for _, o := range n.Blocks.Orders(int64(b)) {
			if o.OrderID == orderID {
				add(o, o.Block, o.Sender)
			}
		}
	}
	return r
}

// OrderSources mirrors GetOrderSources (mpred.pas:933-963).
func (e *Engine) OrderSources(orderID string) string {
	n := e.N
	res := ""
	found := false
	for b := n.MyLastBlock(); b >= n.MyLastBlock()-4000; b-- {
		for _, o := range n.Blocks.Orders(b) {
			if o.OrderID == orderID {
				res += fmt.Sprintf("[%s,%d,%d]", o.Sender, o.AmmountTrf, o.AmmountFee)
				found = true
			}
		}
		if found {
			break
		}
	}
	if !found {
		return "Order Not Found"
	}
	return res
}

// ConnectedPeers mirrors GetConnectedPeers (mpgui.pas:194-207): the IPs of
// every slot whose reported status is at least 3, blank terminated.
func (e *Engine) ConnectedPeers() string {
	res := ""
	for i := 1; i <= MaxConnections; i++ {
		p := e.peers.get(i)
		if p.IP != "" && p.ConexStatus >= 3 {
			res += p.IP + " "
		}
	}
	return res
}

// Int2Curr mirrors nosogeneral.pas:242-248.
func Int2Curr(v int64) string {
	a := v
	if a < 0 {
		a = -a
	}
	s := codec.IntToStr(a)
	for len(s) < 9 {
		s = "0" + s
	}
	s = s[:len(s)-8] + "." + s[len(s)-8:]
	if v < 0 {
		s = "-" + s
	}
	return s
}

var _ = storage.FundsAddress

func sendErrorText(res string) string {
	switch res {
	case "ERROR 19":
		return "could not connect to a node"
	case "ERROR 20":
		return "this node is not up to date yet"
	case "ERROR 21":
		return "no answer from the node"
	}
	return "refused"
}
