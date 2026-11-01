package rpc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// Server is the RPC server (TIdHTTPServer + mprpc.pas).
type Server struct {
	E *network.Engine
	N *node.Node

	mu      sync.Mutex
	srv     *http.Server
	ln      net.Listener
	Log     func(ch, msg string)
	Restart func() // invoked for the "restart" method (RPC_Restart)
}

// New creates a server for an engine.
func New(e *network.Engine) *Server { return &Server{E: e, N: e.N} }

func (s *Server) logf(ch, m string) {
	if s.Log != nil {
		s.Log(ch, m)
	}
}

// Start listens on port (SetRPCOn). It returns an error if the port is busy.
func (s *Server) Start(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return errors.New("RPC server already ENABLED")
	}
	bind := s.N.Options().RPCBind
	if bind == "" {
		bind = "127.0.0.1" // FIX(H-09): loopback unless the operator asks otherwise
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, codec.IntToStr(int64(port))))
	if err != nil {
		return err
	}
	s.ln = ln
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Stop closes the listener (SetRPCOff).
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		_ = s.srv.Close()
		s.srv, s.ln = nil, nil
	}
}

// Active reports whether the server is listening.
func (s *Server) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil
}

// Addr returns the listen address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// MaxBody bounds a request body (hardening).
const MaxBody = 1 << 20

// spendMethods change the wallet or send data to the network and need the
// spend token. FIX(H-09): the original had one shared "password" that was
// never checked at all.
var spendMethods = map[string]bool{"sendfunds": true, "submitorder": true, "submitorderwr": true,
	"setdefault": true, "getnewaddress": true, "getnewaddressfull": true, "restart": true}

// authScope returns 0 for no access, 1 for read and 2 for spend scope. The
// tokens are compared in constant time.
func (s *Server) authScope(h http.Header) int {
	o := s.N.Options()
	got := strings.TrimPrefix(h.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(h.Get("Authorization"), "Bearer ") || got == "" {
		return 0
	}
	eq := func(a string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(got)) == 1 }
	switch {
	case eq(o.RPCSpendToken):
		return 2
	case eq(o.RPCToken):
		return 1
	}
	return 0
}

// handle mirrors TForm1.RPCServerExecute (masterpaskalform.pas:2274-2305)
// behind bearer-token authentication, an Origin ban and a content-type check.
// FIX(H-09): a web page could post to the loopback RPC port (no
// authentication, any content type) and spend the wallet.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	o := s.N.Options()
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	scope := s.authScope(r.Header)
	switch {
	case o.RPCFilter && !ValidRPCHost(o.RPCWhitelist, host):
		io.WriteString(w, ErrorCode(498, -1))
	case r.Header.Get("Origin") != "" || scope == 0:
		io.WriteString(w, ErrorCode(498, -1))
	case r.Method != http.MethodPost:
		io.WriteString(w, ErrorCode(400, -1))
	case !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json"):
		io.WriteString(w, ErrorCode(400, -1))
	default:
		body, _ := io.ReadAll(io.LimitReader(r.Body, MaxBody))
		io.WriteString(w, s.parse(string(body), scope >= 2))
	}
}

// ValidRPCHost mirrors mpcoin.pas:398-414: the ip must appear in the comma
// separated whitelist.
func ValidRPCHost(whitelist, host string) bool {
	// FIX(L7): the host is split with the standard library, so "[::1]:8078"
	// gives "::1" (it used to give "", which matched the end-of-list marker
	// and passed any IPv6 caller). Addresses are compared as addresses.
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return false
	}
	hip := net.ParseIP(h)
	for _, t := range strings.Split(strings.ReplaceAll(whitelist, " ", ""), ",") {
		t = strings.Trim(t, "[]")
		if t == "" {
			continue
		}
		if t == h || (hip != nil && net.ParseIP(t) != nil && net.ParseIP(t).Equal(hip)) {
			return true
		}
	}
	return false
}

// ErrorString mirrors GetJSONErrorString.
func ErrorString(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 401:
		return "Invalid JSON request"
	case 402:
		return "Invalid method"
	case 407:
		return "Send funds failed"
	case 498:
		return "Not authorized"
	case 499:
		return "Unexpected error"
	}
	return "Unknown error code"
}

// ErrorCode mirrors GetJSONErrorCode: {"jsonrpc":"2.0","error":{...},"id":N}.
func ErrorCode(code, id int) string {
	e := (&obj{}).i64("code", int64(code)).str("message", ErrorString(code))
	return (&obj{}).str("jsonrpc", "2.0").add("error", e.String()).i64("id", int64(id)).String()
}

// Response mirrors GetJSONResponse: the result string is split on blanks
// and every item converted by ObjectFromString into one array element.
func Response(result string, id int) string {
	var items []string
	if len(result) > 0 {
		for _, p := range strings.Split(result, " ") {
			if p == "" {
				continue
			}
			js, err := ObjectFromString(p)
			if err != nil {
				return ErrorCode(499, id)
			}
			items = append(items, js)
		}
	}
	return (&obj{}).str("jsonrpc", "2.0").add("result", arr(items)).i64("id", int64(id)).String()
}

// request is the decoded JSON-RPC call.
type request struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
	ID     json.RawMessage   `json:"id"`
}

// paramString mirrors TJSONData.AsString for scalar values.
func paramString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var f any
	if json.Unmarshal(raw, &f) == nil {
		switch v := f.(type) {
		case bool:
			if v {
				return "True"
			}
			return "False"
		case nil:
			return ""
		case float64:
			if v == math.Trunc(v) && math.Abs(v) < 1e18 {
				return codec.IntToStr(int64(v))
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return string(raw)
}

// Parse mirrors ParseRPCJSON (mprpc.pas:~395-450). COMPAT: a request that
// is valid JSON but lacks "method", "params" or an integer "id" makes the
// Pascal code raise inside its try/except, so the HTTP body stays empty.
func (s *Server) Parse(body string) string { return s.parse(body, false) }

func (s *Server) parse(body string, spend bool) string {
	var req request
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(body))
	if err := dec.Decode(&fields); err != nil {
		var generic any
		if json.Unmarshal([]byte(body), &generic) != nil {
			return ErrorCode(401, -1)
		}
		return "" // valid JSON of the wrong shape
	}
	// FIX (Low): text after the JSON value is an error (Pascal: 401), and
	// member names match exactly (encoding/json folds case).
	if _, err := dec.Token(); err != io.EOF {
		return ErrorCode(401, -1)
	}
	if raw, ok := fields["method"]; ok {
		_ = json.Unmarshal(raw, &req.Method)
	}
	if raw, ok := fields["params"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &req.Params) != nil {
			return ""
		}
		if req.Params == nil {
			req.Params = []json.RawMessage{}
		}
	}
	if raw, ok := fields["id"]; ok && string(raw) != "null" {
		req.ID = raw
	}
	if req.Method == "" || req.Params == nil || req.ID == nil {
		return ""
	}
	var idf float64
	if json.Unmarshal(req.ID, &idf) != nil {
		return ""
	}
	id := int(math.Round(idf))
	var ps []string
	for _, p := range req.Params {
		ps = append(ps, paramString(p))
	}
	params := codec.Trim(strings.Join(ps, " "))
	// the original builds " "+p for each and trims, equal to join+trim
	if strings.Contains(s.N.Options().RPCBanned, req.Method) {
		req.Method = "banned"
	}
	if spendMethods[req.Method] && !spend {
		return ErrorCode(498, int(math.Round(idf)))
	}
	res, ok := s.dispatch(req.Method, params)
	if !ok {
		return ErrorCode(402, -1)
	}
	return Response(res, id)
}

func (s *Server) dispatch(method, p string) (string, bool) {
	switch method {
	case "test":
		return "test", true
	case "banned":
		return "banned", true
	case "restart":
		// A front end that cannot restart itself does not install Restart;
		// the method then does not exist rather than answering True and
		// doing nothing (finding 12).
		if s.Restart == nil {
			return "", false
		}
		go s.Restart()
		return "restart", true
	case "getaddressbalance":
		return s.addressBalance(p), true
	case "getorderinfo":
		return s.orderInfo(p), true
	case "getblocksinfo":
		return s.blockInfo(p), true
	case "getmainnetinfo":
		return s.mainnetInfo(), true
	case "getpendingorders":
		return "pendingorders\x7f" + strings.ReplaceAll(network.PendingRawInfo(s.N, true), " ", "\x7f"), true
	case "lockedmns":
		return "lockedmns\x7f" + strings.ReplaceAll(s.N.PSOs.LockedRaw(), " ", "\x7f"), true
	case "getpeers":
		return "peers\x7f" + strings.ReplaceAll(s.E.ConnectedPeers(), " ", "\x7f"), true
	case "getblockorders":
		return s.blockOrders(p), true
	case "getblockmns":
		return s.blockMNs(p), true
	case "getmasternodes":
		return s.masternodes(), true
	case "getwalletbalance":
		return fmt.Sprintf("walletbalance\x7f%d", s.E.WalletBalance()), true
	case "getnewaddress":
		return s.newAddress(p), true
	case "getnewaddressfull":
		return s.newAddressFull(), true
	case "islocaladdress":
		// The wallet in memory is authoritative; the file may be encrypted
		// and cannot be parsed as records (finding 10).
		if s.N.Wallet.IndexOf(codec.Parameter(p, 0)) >= 0 {
			return "islocaladdress\x7fTrue", true
		}
		return "islocaladdress\x7fFalse", true
	case "setdefault":
		if s.setDefault(codec.Parameter(p, 0)) {
			return "setdefault\x7fTrue", true
		}
		return "setdefault\x7fFalse", true
	case "getgvtinfo":
		av := s.N.GVTs.CountAvailable()
		return fmt.Sprintf("gvtinfo\x7f%d\x7f%d\x7f%d", av, storage.GVTPrice(av, false), storage.GVTPrice(av, true)), true
	case "sendfunds":
		return s.sendFunds(p), true
	case "checkcertificate":
		addr, ts := crypto.CheckCertificate(codec.Parameter(p, 0), codec.Parameter(p, 1), codec.Parameter(p, 2))
		if addr != "" {
			return "checkcertificate\x7fTrue\x7f" + addr + "\x7f" + ts, true
		}
		return "checkcertificate\x7fFalse", true
	case "submitorder":
		s.E.SendOrderToNode(p)
		return "submitorder\x7fTrue", true
	case "submitorderwr":
		r := strings.ReplaceAll(s.E.SendOrderToNode(p), " ", "_")
		return "submitorderwr\x7fTrue\x7f" + r, true
	}
	return "", false
}

func (s *Server) addressBalance(p string) string {
	if p == "" {
		return ""
	}
	res := ""
	for i := int64(0); ; i++ {
		a := codec.Parameter(p, i)
		if a == "" {
			break
		}
		var slot int64
		var rec = struct{ Hash, Custom string }{}
		if crypto.IsValidHashAddress(a) {
			sl, r := s.N.Summary.GetIndexPosition(a, false)
			slot, rec.Hash, rec.Custom = sl, r.Hash, r.Custom
		} else {
			sl, r := s.N.Summary.GetIndexPosition(a, true)
			slot, rec.Hash, rec.Custom = sl, r.Hash, r.Custom
			a = r.Hash
		}
		if a == "" {
			break // an unknown alias ends the list (mprpc.pas:542-564)
		}
		var bal, inc, out int64
		alias, valid := "null", "false"
		if slot < 0 {
			bal, inc, out = -1, -1, -1
		} else {
			bal = s.N.Summary.BalanceIndexed(a)
			inc = s.N.AddressIncomingPays(a)
			out = s.N.AddressPendingPays(a)
			if rec.Custom != "" {
				alias = rec.Custom
			}
			valid = "true"
		}
		res += fmt.Sprintf("balance\x7f%s\x7f%s\x7f%s\x7f%d\x7f%d\x7f%d ", valid, a, alias, bal, inc, out)
	}
	return res
}

func (s *Server) orderInfo(p string) string {
	p = codec.Trim(p)
	valid := "true"
	var g network.OrderGroup
	if p == "" {
		valid = "false"
	} else {
		g = s.E.OrderDetails(p)
		if g.OrderID == "" {
			valid = "false"
		}
	}
	return fmt.Sprintf("orderinfo\x7f%s\x7f%s\x7f%d\x7f%d\x7f%s\x7f%d\x7f%s\x7f%d\x7f%d\x7f%s\x7f%s\x7f",
		valid, p, g.TimeStamp, g.Block, g.OrderType, g.OrderLines, g.Receiver, g.AmmountTrf, g.AmmountFee, g.Reference, g.Sender)
}

// blockHeaders mirrors GetBlockHeaders (mpcoin.pas:378-396).
func (s *Server) blockHeaders(n int64) string {
	if !storage.Exists(s.N.Lay.BlockFile(n)) {
		return ""
	}
	h := s.N.Blocks.Header(n)
	hash := crypto.IDHashFile(s.N.Lay.BlockFile(n))
	sol := strings.ReplaceAll(h.Solution, " ", "\x00")
	lbh := strings.ReplaceAll(h.LastBlockHash, " ", "")
	return fmt.Sprintf("%d\x7f%d\x7f%d\x7f%d\x7f%d\x7f%d\x7f%d\x7f%s\x7f%s\x7f%s\x7f%d\x7f%s\x7f%d\x7f%d\x7f%s",
		h.Number, h.TimeStart, h.TimeEnd, h.TimeTotal, h.TimeLast20, h.TrxTotales, h.Difficult, h.TargetHash,
		sol, lbh, h.NxtBlkDiff, h.AccountMiner, h.MinerFee, h.Reward, hash)
}

func (s *Server) blockInfo(p string) string {
	res := ""
	if p == "" {
		return res
	}
	for i := int64(0); ; i++ {
		b := codec.Parameter(p, i)
		if b == "" {
			break
		}
		if v := codec.StrToIntDef(b, -1); v >= 0 && v <= s.N.MyLastBlock() {
			res += "blockinfo\x7ftrue\x7f" + s.blockHeaders(v) + " "
		} else {
			res += "blockinfo\x7ffalse\x7f" + b + "\x7f-1\x7f-1\x7f-1\x7f-1\x7f-1\x7f-1\x7f-1\x7fnull\x7fnull\x7fnull\x7f-1\x7fnull\x7f-1\x7f-1\x7fnull "
		}
	}
	return res
}

func (s *Server) mainnetInfo() string {
	g := s.E.GetConsensus
	return fmt.Sprintf("mainnetinfo\x7f%s\x7f%s\x7f%s\x7f%s\x7f%s\x7f%d", g(2), codec.Copy(g(10), 0, 5),
		codec.Copy(g(15), 0, 5), codec.Copy(g(17), 0, 5), g(3), consensus.GetSupply(codec.StrToIntDef(g(2), 0)))
}

func (s *Server) blockOrders(p string) string {
	bn := codec.StrToIntDef(p, -1)
	if bn < 0 || bn > s.N.MyLastBlock() {
		return "blockorder\x7ffalse\x7f" + p + "\x7f0"
	}
	orders := s.N.Blocks.Orders(bn)
	res := "blockorder\x7ftrue\x7f" + p + "\x7f"
	if len(orders) == 0 {
		return res + "0\x7f"
	}
	type grp struct {
		id, typ, recv, ref, sender string
		ts                         int64
		block, lines               int32
		trf, fee                   int64
	}
	// FIX(re2 H-2): lines are merged into one order only when they agree on id,
	// receiver, type and time (a block of this chain guarantees it; a legacy
	// or foreign block may not). Fields are cleaned of the record separators
	// so a field can never start another record.
	clean := func(v string) string {
		return strings.Map(func(r rune) rune {
			if r == 0x7f || r == ' ' || r == '\x00' || r < 0x20 {
				return '_'
			}
			return r
		}, v)
	}
	var groups []*grp
	for _, o := range orders {
		o.OrderID, o.Reference, o.Sender, o.Receiver, o.Address = clean(o.OrderID), clean(o.Reference), clean(o.Sender), clean(o.Receiver), clean(o.Address)
		var g *grp
		for _, x := range groups {
			if x.id == o.OrderID && x.recv == o.Receiver && x.typ == o.OrderType && x.ts == o.TimeStamp {
				g = x
				break
			}
		}
		if g != nil {
			g.trf += o.AmmountTrf
			g.fee += o.AmmountFee
			g.sender += fmt.Sprintf("[%s,%d,%d]", o.Address, o.AmmountTrf, o.AmmountFee)
			g.lines++
			continue
		}
		g = &grp{id: o.OrderID, ts: o.TimeStamp, block: o.Block, typ: o.OrderType, lines: 1, recv: o.Receiver,
			trf: o.AmmountTrf, fee: o.AmmountFee, ref: o.Reference}
		if o.OrderLines == 1 {
			g.sender = o.Sender
		} else {
			g.sender = fmt.Sprintf("[%s,%d,%d]", o.Address, o.AmmountTrf, o.AmmountFee)
		}
		groups = append(groups, g)
	}
	res += fmt.Sprintf("%d\x7f", len(groups))
	for _, g := range groups {
		res += fmt.Sprintf("%s\x7f%d\x7f%d\x7f%s\x7f%d\x7f%s\x7f%d\x7f%d\x7f%s\x7f%s\x7f", g.id, g.ts, g.block, g.typ,
			g.lines, g.recv, g.trf, g.fee, g.ref, g.sender)
	}
	return res
}

func (s *Server) blockMNs(p string) string {
	bn := codec.StrToIntDef(p, -1)
	if bn < 48010 || bn > s.N.MyLastBlock() {
		return "blockmns\x7ffalse\x7f" + p + "\x7f0\x7f0\x7f0"
	}
	blk, _ := s.N.Blocks.Read(bn)
	if blk == nil {
		return "blockmns\x7ffalse\x7f" + p + "\x7f0\x7f0\x7f0"
	}
	cnt := int64(len(blk.MNsAddrs))
	return fmt.Sprintf("blockmns\x7ftrue\x7f%d\x7f%d\x7f%d\x7f%d\x7f%s", bn, cnt, blk.MNsPay, cnt*blk.MNsPay,
		strings.Join(blk.MNsAddrs, ","))
}

func (s *Server) masternodes() string {
	src := s.N.MNFile.Text()
	block := codec.Parameter(src, 0)
	nodes := ""
	total := 0
	for i := int64(1); ; i++ {
		d := codec.Parameter(src, i)
		if d == "" {
			break
		}
		d = strings.ReplaceAll(d, ":", " ")
		ipp := strings.ReplaceAll(codec.Parameter(d, 0), ";", " ")
		nodes += fmt.Sprintf("[%s,%s,%s,%s]", codec.Parameter(ipp, 0), codec.Parameter(ipp, 1), codec.Parameter(d, 1), codec.Parameter(d, 2))
		total++
	}
	return fmt.Sprintf("getmasternodes\x7f%s\x7f%d\x7f%s", block, total, nodes)
}

func (s *Server) newAddress(p string) string {
	total := int(codec.StrToIntDef(p, 1))
	if total > 100 {
		total = 100
	}
	res := fmt.Sprintf("newaddress\x7ftrue\x7f%d\x7f", total)
	for i := 0; i < total; i++ {
		w, err := s.E.NewAddress() // saved with the wallet, which is encrypted
		if err != nil {
			s.logf("exceps", "new address not saved: "+err.Error())
			return "newaddress\x7ffalse\x7f0\x7f"
		}
		res += w.Hash + "\x7f"
	}
	return res
}

func (s *Server) newAddressFull() string {
	w, err := s.E.NewAddress()
	if err != nil {
		s.logf("exceps", "new address not saved: "+err.Error())
		return "newaddressfull\x7ffalse"
	}
	priv := ""
	if s.N.Options().RPCExposeKeys { // FIX(H-09, H-10): keys are not sent over RPC by default
		priv = w.PrivateKey
	}
	return "newaddressfull\x7f" + w.Hash + "\x7f" + w.PublicKey + "\x7f" + priv
}

// setDefault mirrors SetDefaultAddress: move the address to wallet slot 0.
func (s *Server) setDefault(addr string) bool {
	idx := s.N.Wallet.IndexOf(addr)
	if idx < 0 || idx > s.N.Wallet.Len()-1 || idx == 0 {
		return false
	}
	if s.N.Wallet.Swap(0, idx) {
		return s.N.Wallet.SaveErr() == nil
	}
	return false
}

func (s *Server) sendFunds(p string) string {
	dest := codec.Parameter(p, 0)
	amount := codec.StrToInt64Def(codec.Parameter(p, 1), 0)
	ref := codec.Parameter(p, 2)
	if ref == "" {
		ref = "null"
	}
	res := s.E.SendFunds(fmt.Sprintf("sendto %s %d %s", dest, amount, ref), func(l string) { s.logf("console", l) }, 0)
	switch {
	case res != "" && codec.Parameter(res, 0) != "ERROR" && codec.Copy(res, 0, 2) == "OR":
		return "sendfunds\x7f" + res
	case codec.Parameter(res, 0) == "ERROR":
		return "sendfunds\x7fERROR\x7f" + codec.IntToStr(codec.StrToIntDef(codec.Parameter(res, 1), 0))
	}
	return "sendfunds\x7fERROR\x7f999"
}
