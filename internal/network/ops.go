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

// ParseAmount converts a user-typed amount to base units (1 NOSO =
// 100000000 units), exactly and without floating point. "1", "1.5" and
// "0.00000001" are NOSO (at most 8 decimals); a trailing u gives base units
// ("150000000u"). It refuses signs, exponents, spaces and anything that does
// not fit.
func ParseAmount(s string) (int64, error) {
	const unit = 100000000
	if s == "" {
		return 0, fmt.Errorf("no amount")
	}
	if units, ok := strings.CutSuffix(s, "u"); ok {
		v, ok := codec.StrToInt64(units)
		if !ok || v <= 0 || !digitsOnly(units) {
			return 0, fmt.Errorf("%q is not a whole number of base units", s)
		}
		return v, nil
	}
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" || !digitsOnly(whole) || (frac != "" && !digitsOnly(frac)) || strings.HasSuffix(s, ".") {
		return 0, fmt.Errorf("%q is not an amount in NOSO", s)
	}
	if len(frac) > 8 {
		return 0, fmt.Errorf("%q has more than 8 decimals", s)
	}
	frac += strings.Repeat("0", 8-len(frac))
	w, ok := codec.StrToInt64(whole)
	if !ok || w > consensus.MaxSupply/unit {
		return 0, fmt.Errorf("%q is too large", s)
	}
	f, _ := codec.StrToInt64(frac)
	if v := w*unit + f; v > 0 {
		return v, nil
	}
	return 0, fmt.Errorf("the amount must be above zero")
}

func digitsOnly(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
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
			say.say("The wallet cannot cover this amount and fee right now: orders still waiting to be mined hold part of the balance. Try again after the next block.")
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
	_ = orderHashString
	// the lines are numbered, signed with the line count and given the id
	// derived from all of them: the pool, the builder and the validators check
	// exactly that
	trfrs, err := n.SealOrder(trfrs)
	if err != nil {
		say.say("The order could not be built: %v", err)
		return ""
	}
	orderID := trfrs[0].OrderID
	os := node.PTCHeader(n) + "ORDER " + codec.IntToStr(int64(line_)) + " $"
	for _, o := range trfrs {
		os += types.StringFromOrder(o) + " $"
	}
	os = os[:len(os)-2]
	os = strings.Replace(os, "PSK", "NSLORDER", 1)
	if e.TraceOrder != nil {
		e.TraceOrder(os)
	}
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

// SendGVT mirrors SendGVT (mpparser.pas:~870-935). The order is signed with
// the canonical GVT number (the builder and the validators read nothing
// else), admitted to this node's pool exactly as a received one is and
// announced to the peers, whose dispatcher takes it as `$SNDGVT`.
func (e *Engine) SendGVT(line string, say Printer) string {
	n := e.N
	arg := codec.Parameter(line, 1)
	num := int(codec.StrToIntDef(arg, -1))
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
	fee := consensus.GetCustFee(n.MyLastBlock() + 1)
	if n.AddressAvailable(g.Owner) < fee {
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
	// FIX(GAP-3): the reference is the canonical number ("5"), not the file's
	// zero-padded "05", which the builder refuses.
	o := types.Order{OrderLines: 1, OrderType: "SNDGVT", TimeStamp: ts, Reference: codec.IntToStr(int64(num)), TrxLine: 1,
		Sender: w.PublicKey, Address: w.Hash, Receiver: dest, AmmountFee: fee}
	node.SignOrder(n.ChainID(), &o, w.PrivateKey)
	o.OrderID = node.SingleOrderID(o.TrfrID)
	o.Normalize()
	return e.admitSingle(say, "SNDGVT", o, n.PTCSendGVT, func() string {
		return fmt.Sprintf("GVT %s transfered from %s to %s\nOrder: %s", o.Reference, w.Hash, dest, o.OrderID)
	})
}

// admitSingle puts a CUSTOM or SNDGVT order into this node's pool through the
// same admission as one received from a peer, and tells the peers when the
// node itself did not (a node that does not serve announces nothing on its
// own). It returns the order id, "" when the order was refused.
func (e *Engine) admitSingle(say Printer, what string, o types.Order, admit func(string) int, done func() string) string {
	op := "$" + types.StringFromOrder(o)
	if code := admit(op); code != 0 {
		say.say("The %s order was refused (code %d)", what, code)
		return ""
	}
	if !e.ServerActive() {
		e.OutgoingAdd(node.PTCHeader(e.N) + op)
	}
	say.say("%s", done())
	return o.OrderID
}

// Customize mirrors CustomizeAddress (mpparser.pas:~640-720) combined with
// the crypto worker that signs and broadcasts the CUSTOM order. The funds are
// checked against the summary, the same balance the pool admits the order
// against (FIX(GAP-4): the wallet record's own Balance is never maintained).
func (e *Engine) Customize(line string, say Printer) bool {
	n := e.N
	addr, alias := codec.Parameter(line, 1), codec.Parameter(line, 2)
	ok := true
	idx := n.Wallet.IndexOf(addr)
	if idx < 0 {
		say.say("Invalid address")
		return false
	}
	w := n.Wallet.At(idx)
	fee := consensus.GetCustFee(n.MyLastBlock() + 1)
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
	if n.AddressAvailable(w.Hash) < fee {
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
		Sender: w.PublicKey, Address: w.Hash, Receiver: alias, AmmountFee: fee}
	node.SignOrder(n.ChainID(), &o, w.PrivateKey)
	o.OrderID = node.SingleOrderID(o.TrfrID)
	o.Normalize()
	return e.admitSingle(say, "CUSTOM", o, n.PTCCustom, func() string { return "Customization sent" }) != ""
}

// NewPSO signs a NEWPSO order for a wallet address, admits it to this node's
// pool like one received from a peer and announces it. A proposer mines it into
// a block; only then does the PSO exist, on every node.
func (e *Engine) NewPSO(addr string, mode int, params string, say Printer) bool {
	o, err := e.N.NewPSOOrder(addr, mode, params)
	if err != nil {
		say.say("The PSO order could not be built: %v", err)
		return false
	}
	return e.admitSingle(say, "NEWPSO", o, e.N.PTCPSO, func() string {
		return "PSO order sent: " + o.OrderID + " (the PSO exists once a block holds it)"
	}) != ""
}

// ClearPSOs signs a CLRPSO order that removes the PSOs of a wallet address.
func (e *Engine) ClearPSOs(addr string, say Printer) bool {
	o, err := e.N.ClearPSOsOrder(addr)
	if err != nil {
		say.say("The PSO order could not be built: %v", err)
		return false
	}
	return e.admitSingle(say, "CLRPSO", o, e.N.PTCPSO, func() string {
		return "Clear order sent: " + o.OrderID + " (your PSOs go once a block holds it)"
	}) != ""
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

// OrderErrorText explains the answer of a node to an order ("ERROR n").
func OrderErrorText(res string) string {
	m := map[string]string{
		"ERROR 1":   "not enough spendable funds (amount plus fee, minus orders still waiting for a block)",
		"ERROR 2":   "the same order is already waiting",
		"ERROR 3":   "the order is older than the last block",
		"ERROR 4":   "the order is dated more than a minute ahead of this node's clock; check the clock",
		"ERROR 5":   "the same order was mined recently",
		"ERROR 7":   "negative amount",
		"ERROR 8":   "negative fee",
		"ERROR 9":   "the sender is not a valid address",
		"ERROR 10":  "the receiver is not a regular address",
		"ERROR 11":  "the sender address is locked",
		"ERROR 12":  "the network is stopped",
		"ERROR 13":  "the sender does not match the signing key",
		"ERROR 15":  "amount plus fee overflows",
		"ERROR 16":  "wrong order type",
		"ERROR 19":  "could not connect to a node",
		"ERROR 20":  "this node is not up to date yet",
		"ERROR 21":  "no answer from the node",
		"ERROR 89":  "more than 30 lines",
		"ERROR 96":  "the order could not be parsed",
		"ERROR 102": "bad reference or several receivers in one order",
		"ERROR 103": "the lines of the order disagree",
		"ERROR 104": "the pool is full or the order is too old for this period",
	}
	if t, ok := m[strings.TrimSpace(res)]; ok {
		return t
	}
	return "refused"
}

func sendErrorText(res string) string { return OrderErrorText(res) }
