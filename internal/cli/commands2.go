package cli

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func serverOn(d *Dispatcher) bool { return d.E != nil && d.E.ServerActive() }

// cmdStatus mirrors GetCurrentStatus(1) (mpcoin.pas:363-376).
func cmdStatus(d *Dispatcher, l string) {
	d.log("ServerON    : %s ", boolStr(serverOn(d)))
	d.log("Date        : %s", time.Now().Format("02 January 2006 15:04:05.000"))
	d.log("MyConStatus : %d", d.N.ConStatus())
	d.log("OS          : %s", osVersion())
	d.log("WalletVer   : %s", node.MainnetVersion+node.NodeRelease)
}

// cmdSystem mirrors ShowSystemInfo (mpparser.pas:1727-1745): only while the
// node has no connections.
func cmdSystem(d *Dispatcher, l string) {
	if d.N.ConStatus() > 0 {
		return
	}
	switch codec.ASCIIUpper(p(l, 1)) {
	case "POWER":
		start := time.Now()
		var wg sync.WaitGroup
		cores := 4
		for c := 0; c < cores; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 1; i <= 10000; i++ {
					sha256.Sum256([]byte(codec.IntToStr(int64(i))))
				}
			}()
		}
		wg.Wait()
		ms := time.Since(start).Milliseconds()
		if ms < 1 {
			ms = 1
		}
		d.log("Processing       : %d Trx/s", int64(cores*10000)/ms)
	case "MEM":
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		d.log("Available memory : %d MB", (m.Sys-m.HeapInuse)/1048576)
	case "DOWNSPEED":
		start := time.Now()
		cl := http.Client{Timeout: 5 * time.Second}
		resp, err := cl.Get("https://raw.githubusercontent.com/nosocoin/NosoNode/main/1mb.dat")
		if err != nil {
			d.log("Download speed   : 0 Kb/s")
			return
		}
		defer func() { _ = resp.Body.Close() }() // the body is read; nothing is lost by a failed close
		n, _ := io.Copy(io.Discard, resp.Body)
		ms := time.Since(start).Milliseconds()
		if ms < 1 {
			ms = 1
		}
		d.log("Download speed   : %d Kb/s", n/ms)
	default:
		d.fail("Invalid parameter: %s\nUse: power, mem or downspeed", codec.ASCIIUpper(p(l, 1)))
	}
}

// FetchSeeds downloads a seed list and its detached signature (url + ".sig",
// Base64) and returns the list only if the signature verifies under the
// release key. FIX(M-02): the original fetched an unauthenticated list with
// certificate checks off (nosonosocfg.pas:81, mpred.pas:1008-1025).
func FetchSeeds(url, releaseKey string) string {
	if releaseKey == "" || !strings.HasPrefix(url, "https://") {
		return ""
	}
	get := func(u string) string {
		resp, err := seedHTTPClient.Get(u)
		if err != nil {
			return ""
		}
		defer func() { _ = resp.Body.Close() }() // the body is read; nothing is lost by a failed close
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return codec.Trim(string(b))
	}
	list, sig := get(url), get(url+".sig")
	if list == "" || !crypto.VerifyCanonical(releaseKey, sig, "SEEDS1", list) {
		return ""
	}
	return list
}

// FetchDefaultSeeds is kept for callers that have no URL configured: nothing
// is downloaded.
func FetchDefaultSeeds() string { return "" }

func walletBalance(d *Dispatcher) int64 {
	var total int64
	for _, w := range d.N.Wallet.All() {
		total += d.N.Summary.BalanceIndexed(w.Hash)
	}
	return total - d.N.MontoOutgoing
}

func newWalletAddress(d *Dispatcher) (types.Wallet, error) { return d.N.Wallet.NewAddress() }

func cmdShowWallet(d *Dispatcher, l string) {
	for _, w := range d.N.Wallet.All() {
		d.log("%s", w.Hash)
	}
	d.log("%d addresses.", d.N.Wallet.Len())
	d.log("%s NOSO", i2c(walletBalance(d)))
}

// cmdExpWallet writes the addresses as a plaintext .pkw file, the format
// impwallet reads (mpparser.pas:431-448). It never overwrites a file.
func cmdExpWallet(d *Dispatcher, l string) {
	dest := strings.ReplaceAll(p(l, 1), "*", " ")
	if dest == "" {
		d.fail("Syntax: expwallet {destination}")
		return
	}
	if err := d.N.Wallet.ExportPKW(dest + ".pkw"); err != nil {
		if errors.Is(err, os.ErrExist) {
			d.fail("Error: Can not overwrite existing wallets")
		} else {
			d.fail("Failed: %v", err)
		}
		return
	}
	d.log("Wallet saved as %s.pkw", dest)
	d.log("%s", storage.PKWExportWarning)
}

func cmdImpWallet(d *Dispatcher, l string) {
	path := strings.ReplaceAll(p(l, 1), "*", " ")
	raw, err := os.ReadFile(path)
	if err != nil {
		d.log("Specified wallet file do not exists.")
		return
	}
	recs, err := storage.ParsePKW(raw)
	if err != nil || !crypto.IsValidHashAddress(recs[0].Hash) {
		d.log("The file is not a valid wallet")
		return
	}
	added := 0
	for _, w := range recs {
		if crypto.IsValidHashAddress(w.Hash) {
			ok, err := d.N.Wallet.Add(w)
			if err != nil {
				d.fail("Wallet not saved: %v", err)
				break
			}
			if ok {
				added++
			}
		}
	}
	if added > 0 {
		d.log("Addresses imported: %d", added)
	} else {
		d.log("No new addreses found.")
	}
}

func setDefault(d *Dispatcher, l string) bool {
	idx := d.N.Wallet.IndexOf(p(l, 1))
	switch {
	case idx < 0 || idx > d.N.Wallet.Len()-1:
		d.fail("Invalid address.")
	case idx == 0:
		d.log("Address is already the default.")
	default:
		if d.N.Wallet.Swap(0, idx) {
			d.N.Wallet.Save()
			return true
		}
	}
	return false
}

func showKeys(d *Dispatcher, l string) {
	i := d.N.Wallet.IndexOf(p(l, 1))
	if i < 0 {
		d.fail("Address not found in wallet")
		return
	}
	w := d.N.Wallet.At(i)
	d.log("%s %s", w.PublicKey, w.PrivateKey)
}

// cmdGetMulti mirrors CreateMultiAddress (mpparser.pas:1862-1900).
func cmdGetMulti(d *Dispatcher, l string) {
	t := strings.ReplaceAll(p(l, 1), ",", " ")
	needed, total := codec.StrToIntDef(codec.Parameter(t, 0), -1), codec.StrToIntDef(codec.Parameter(t, 1), -1)
	msg := ""
	if t == "" {
		msg = "getmulti needed,total list,of,addresses"
	}
	if total < 2 || total > 7 {
		msg = "Wrong number of total addresses"
	}
	if needed < 1 || needed >= total {
		msg = "Wrong number of needed addresses"
	}
	if msg != "" {
		d.log("%s", msg)
		return
	}
	full, ok := crypto.GetMultiSource(p(l, 2), int(total))
	if !ok {
		d.fail("Error: %s", full)
		return
	}
	t = strings.ReplaceAll(t, " ", ",")
	key := t + ":" + full
	addr := crypto.GetAddressFromPublicKey(key, crypto.AddTypeMulti)
	if crypto.IsValidHashAddress(addr) {
		d.log("New multiAddress: %s", addr)
		if _, err := d.N.Wallet.Add(types.Wallet{Hash: addr, PublicKey: key}); err != nil {
			d.fail("Wallet not saved: %v", err)
		}
	} else {
		d.log("Something went wrong...")
	}
}

// cmdResumen mirrors ShowBlchHead (mpparser.pas:469-497).
func cmdResumen(d *Dispatcher, l string) {
	start := int(codec.StrToIntDef(p(l, 1), d.N.MyLastBlock())) - 10
	if start < 0 {
		start = 0
	}
	all := d.N.Headers.All()
	errs := 0
	if start >= len(all) {
		d.fail("Error: Seek past end of file")
		return
	}
	for i := start; i < len(all); i++ {
		r := all[i]
		d.log("%d %s %s", r.Block, codec.Copy(r.BlockHash, 1, 5), codec.Copy(r.SumHash, 1, 5))
		if r.BlockHash == "MISS" {
			errs++
		}
		if r.SumHash == "MISS" {
			errs++
		}
	}
	d.fail("Errors : %d", errs)
}

func showBlockInfo(d *Dispatcher, n int64) {
	if !storage.Exists(d.N.Lay.BlockFile(n)) {
		d.log("Block file do not exists: %d", n)
		return
	}
	b, _ := d.N.Blocks.Read(n)
	if b == nil {
		return
	}
	h := b.Header
	d.log("Block info: %d", n)
	d.log("Hash  :       %s", crypto.IDHashFile(d.N.Lay.BlockFile(n)))
	d.log("Number:       %d", h.Number)
	d.log("Time start:   %d (%s)", h.TimeStart, timestampToDate(h.TimeStart))
	d.log("Time end:     %d (%s)", h.TimeEnd, timestampToDate(h.TimeEnd))
	d.log("Time total:   %d", h.TimeTotal)
	d.log("L20 average:  %d", h.TimeLast20)
	d.log("Transactions: %d", h.TrxTotales)
	d.log("Difficult:    %d", h.Difficult)
	d.log("Target:       %s", h.TargetHash)
	d.log("Solution:     %s", h.Solution)
	d.log("Last Hash:    %s", h.LastBlockHash)
	d.log("Next Diff:    %d", h.NxtBlkDiff)
	d.log("Miner:        %s", h.AccountMiner)
	d.log("Fees:         %d", h.MinerFee)
	d.log("Reward:       %d", h.Reward)
	if len(b.Orders) > 0 {
		d.log("TRANSACTIONS")
		for _, o := range b.Orders {
			d.log("%-8s %-35s -> %-35s : %s", o.OrderType, o.Sender, o.Receiver, i2c(o.AmmountTrf))
		}
	}
	if n > consensus.PoSBlockStart {
		d.log("PoS Reward: %s  /  Addresses: %d  /  Total: %s", i2c(b.PosPay), len(b.PosAddrs), i2c(b.PosPay*int64(len(b.PosAddrs))))
	}
	if n > consensus.MNBlockStart {
		d.log("MNs Reward: %s  /  Addresses: %d  /  Total: %s", i2c(b.MNsPay), len(b.MNsAddrs), i2c(b.MNsPay*int64(len(b.MNsAddrs))))
	}
}

func cmdHalving(d *Dispatcher, l string) {
	var cap int64
	for c := int64(0); c <= consensus.HalvingSteps; c++ {
		b1 := consensus.BlockHalvingInterval * c
		if b1 == 0 {
			b1 = 1
		}
		b2 := consensus.BlockHalvingInterval*(c+1) - 1
		reward := int64(consensus.InitialReward) / (int64(1) << uint(c))
		cap += reward * consensus.BlockHalvingInterval
		d.log("From block %7d until %7d : %11s", b1, b2, i2c(reward))
	}
	d.log("And then %s", i2c(0))
	cap += consensus.PremineAmount - consensus.InitialReward
	d.log("Final supply: %s", i2c(cap))
}

func cmdGMTS(d *Dispatcher, l string) {
	monto := codec.StrToInt64Def(p(l, 1), 0)
	g := consensus.GetMaximunToSend(monto)
	fee := monto - g
	if fee < 1000000 {
		fee = 1000000
	}
	if monto <= 1000000 {
		g, fee = 0, 0
	}
	d.log("Ammount         : %s", i2c(monto))
	d.log("Maximun to send : %s", i2c(g))
	d.log("Fee paid        : %s", i2c(fee))
	if g+fee == monto {
		d.log("✓ Match")
	} else {
		d.log("✗ Error")
	}
}

func cmdAddress(d *Dispatcher, l string) {
	show := p(l, 1)
	var hash, alias string
	var slot int64
	var rec types.Summary
	if crypto.IsValidHashAddress(show) {
		hash = show
		alias = d.N.Summary.Alias(show)
		slot, rec = d.N.Summary.GetIndexPosition(show, false)
	} else {
		slot, rec = d.N.Summary.GetIndexPosition(show, true)
		if slot >= 0 {
			hash, alias = rec.Hash, show
		}
	}
	if slot < 0 {
		d.log("Address do not exists in sumary.")
		return
	}
	on := d.N.Summary.BalanceIndexed(hash)
	pend := d.N.AddressPendingPays(hash)
	d.log("Address   : %s\nAlias     : %s\nSummary   : %s (%d)\nIncoming  : %s\nOutgoing  : %s\nAvailable : %s",
		hash, alias, i2c(on), slot, i2c(d.N.AddressIncomingPays(hash)), i2c(pend), i2c(on-pend))
	if strings.Contains(d.N.MNFile.Text(), hash) {
		d.log("Masternode: Active")
	}
	var owned []string
	for i, g := range d.N.GVTs.All() {
		if g.Owner == hash {
			owned = append(owned, codec.IntToStr(int64(i)))
		}
	}
	if len(owned) > 0 {
		d.log("GVTs      : %s", strings.Join(owned, " "))
	}
}

// cmdHistory mirrors ShowAddressHistory (mpparser.pas:1280-1380).
func cmdHistory(d *Dispatcher, l string) {
	n := d.N
	count := codec.StrToIntDef(p(l, 2), 0)
	if count == 0 {
		count = consensus.SecurityBlocks - 1
	}
	if count >= n.MyLastBlock() {
		count = n.MyLastBlock() - 1
	}
	addr := p(l, 1)
	var mined, inTrx, outTrx, posPays int
	var inCoins, outCoins, posEarn int64
	minedStr := ""
	var trans []string
	for c := n.MyLastBlock(); c >= n.MyLastBlock()-count; c-- {
		b, _ := n.Blocks.Read(c)
		if b == nil {
			b = &storage.Block{Header: n.Blocks.Header(c), Orders: n.Blocks.Orders(c)}
		}
		if b.Header.AccountMiner == addr {
			mined++
			minedStr += codec.IntToStr(c) + " "
			inCoins += b.Header.Reward + b.Header.MinerFee
		}
		for _, o := range b.Orders {
			if o.Receiver == addr {
				inTrx++
				inCoins += o.AmmountTrf
				trans = append(trans, codec.IntToStr(c)+"] "+o.Sender+"<-- "+i2c(o.AmmountTrf))
			}
			if o.Sender == addr {
				outTrx++
				outCoins += o.AmmountTrf + o.AmmountFee
				trans = append(trans, codec.IntToStr(c)+"] "+o.Receiver+"--> "+i2c(o.AmmountTrf))
			}
		}
		if c >= consensus.PoSBlockStart {
			for _, a := range b.PosAddrs {
				if a == addr {
					posPays++
					posEarn += b.PosPay
				}
			}
		}
	}
	d.log("Last block : %d", n.MyLastBlock())
	d.log("Address    : %s", addr)
	d.log("INCOMINGS")
	d.log("  Mined        : %d", mined)
	d.log("  Mined blocks : %s", minedStr)
	d.log("  Transactions : %d", inTrx)
	d.log("  Coins        : %s", i2c(inCoins))
	d.log("  PoS Payments : %d", posPays)
	d.log("  PoS Earnings : %s", i2c(posEarn))
	d.log("OUTGOINGS")
	d.log("  Transactions : %d", outTrx)
	d.log("  Coins        : %s", i2c(outCoins))
	d.log("TOTAL  : %s", i2c(inCoins-outCoins+posEarn))
	d.log("SUMARY : %s", i2c(n.Summary.BalanceIndexed(addr)))
	d.log("")
	d.log("Transactions")
	for _, t := range trans {
		d.log("%s", t)
	}
}

func cmdTotalFees(d *Dispatcher, l string) {
	var total int64
	last := d.N.MyLastBlock()
	for c := int64(1); c <= last; c++ {
		total += d.N.Blocks.Header(c).MinerFee
	}
	d.log("Blockchain total fees: %s", i2c(total))
	if last > 0 {
		d.log("Block average        : %s", i2c(total/last))
	}
}

func showBlockTail(d *Dispatcher, l string, pos bool) {
	n := codec.StrToIntDef(p(l, 1), 0)
	min := int64(consensus.MNBlockStart)
	if pos {
		min = consensus.PoSBlockStart
	}
	if n < min || n > d.N.MyLastBlock() {
		d.fail("Invalid block number: %d", n)
		return
	}
	b, _ := d.N.Blocks.Read(n)
	if b == nil {
		return
	}
	addrs, rew := b.MNsAddrs, b.MNsPay
	if pos {
		addrs, rew = b.PosAddrs, b.PosPay
	}
	for _, a := range addrs {
		if pos {
			d.log("%s: %s", a, i2c(rew))
		} else {
			d.log("%s", a)
		}
	}
	if pos {
		d.log("Block:   : %d", n)
		d.log("Addresses: %d", len(addrs))
		d.log("Reward   : %s", i2c(rew))
		d.log("Total    : %s", i2c(int64(len(addrs))*rew))
	} else {
		d.log("MNs Block : %d", n)
		d.log("Addresses : %d", len(addrs))
		d.log("Reward    : %s", i2c(rew))
		d.log("Total     : %s", i2c(int64(len(addrs))*rew))
	}
}

// cmdSumary mirrors ShowSumary (mpparser.pas:1760-1850).
func cmdSumary(d *Dispatcher, l string) {
	var total, nodeAmt, snAmt, nanoAmt, oldAmt int64
	var neg, empty, short, nodeAddr, snAddr, nanoAddr, nano int
	last := int64(-1)
	all := d.N.Summary.All()
	for _, r := range all {
		if last < 0 {
			last = r.LastOP
		}
		if r.Balance < 0 {
			neg++
		}
		if r.Balance == 0 {
			empty++
		}
		total += r.Balance
		if len(r.Hash) < 28 {
			short++
			d.log("%s", r.Hash)
		}
		if r.Balance > 0 && r.Balance < 101 {
			nano++
		}
		switch {
		case r.Balance >= 1050000000000:
			nodeAddr++
			nodeAmt += r.Balance
		case r.Balance >= 10500000000:
			snAddr++
			snAmt += r.Balance
		case r.Balance > 0:
			nanoAddr++
			nanoAmt += r.Balance
		}
		if r.LastOP < 10000 && r.Balance > 100000000 {
			oldAmt += r.Balance
		}
		if !crypto.IsValidHashAddress(r.Hash) {
			d.log("%s", r.Hash)
		}
	}
	d.log("Total old: %s", i2c(oldAmt))
	as := "✓"
	if exp := consensus.GetSupply(d.N.MyLastBlock()); total != exp {
		as = "(" + i2c(total-exp) + ")"
	}
	d.log("Block : %d (short: %d)", last, short)
	d.log("%s NOSO %s", i2c(total), as)
	d.log("Addresses (%d): %d (%d empty)", neg, len(all), empty)
	d.log(">= 10500      : %d (%s Noso)", nodeAddr, i2c(nodeAmt))
	d.log("105 - 10500   : %d (%s Noso)", snAddr, i2c(snAmt))
	d.log("<105          : %d (%s Noso)", nanoAddr, i2c(nanoAmt))
	d.log("Nano          : %d ", nano)
}

func gvtInfo(d *Dispatcher) {
	av := d.N.GVTs.CountAvailable()
	d.log("Available: %d", av)
	d.log("Buy  : %s", i2c(storage.GVTPrice(av, false)))
	d.log("Sell : %s", i2c(storage.GVTPrice(av, true)))
}

func cmdFreezed(d *Dispatcher, l string) {
	var total int64
	count := 0
	for i := int64(0); ; i++ {
		a := codec.Parameter(d.N.CFG.Param(5), i, ':')
		if a == "" {
			break
		}
		bal := d.N.Summary.BalanceIndexed(a)
		total += bal
		count++
		mn := ""
		if strings.Contains(d.N.MNFile.Text(), a) {
			mn = "[MN]"
		}
		d.log("%-35s : %15s  [%5d] %s", a, i2c(bal), d.N.Summary.AddressLastOP(a), mn)
	}
	d.log("Freezed %d : %s", count, i2c(total))
}

func cmdConsensus(d *Dispatcher, l string) {
	if !d.needNet() {
		return
	}
	s := d.E.ConsStats()
	d.log("(%d / %d) %d %%", s.ReachedNodes, s.TotalNodes, s.Percentage)
	for i, v := range d.E.ConsensusItems() {
		name := ""
		if i < len(network.NConsensus) {
			name = network.NConsensus[i]
		}
		d.log("%2d %12s -> %s", i, name, v)
	}
}

func restoreSummary(d *Dispatcher) {
	d.log("Restoring sumary from %d", ((d.N.Blocks.LastUpdated()/consensus.SumMarkInterval)-1)*consensus.SumMarkInterval)
	if err := d.N.CompleteSummary(); err != nil {
		d.log("complete summary: %v", err)
	}
}

// cmdRestoreChain mirrors RestoreBlockChain (mpdisk.pas:795-807): the
// summary, headers and every block are deleted; the daemon restarts.
func cmdRestoreChain(d *Dispatcher, l string) {
	// FIX(M5): this deletes the whole chain, so it asks for a confirmation,
	// needs a front end that can restart the node (otherwise the running node
	// would keep working on deleted files) and removes every file derived
	// from the blocks, not just some of them.
	if strings.ToLower(p(l, 1)) != "confirm" {
		d.log("This deletes the blockchain and all state derived from it. Run `restoreblockchain confirm`.")
		return
	}
	if d.Quit == nil || !d.CanRestart {
		d.log("This program cannot restart the node; stop it and start it again after running the command in nosocli with no daemon running.")
		if d.E != nil {
			return
		}
	}
	if d.E != nil {
		d.E.StopServer()
	}
	lay := d.N.Lay
	for _, f := range []string{lay.Summary, lay.Summary + ".bak", lay.Headers, lay.GVTs, lay.PSOs,
		filepath.Join(lay.Root, "highwater.seq")} {
		_ = os.Remove(f)
	}
	_ = os.RemoveAll(lay.BlockDir)
	_ = os.RemoveAll(filepath.Join(lay.Root, "UNDO"))
	if d.Quit != nil && d.CanRestart {
		d.Quit(true)
	} else {
		d.log("Blockchain files deleted; start nosod to resynchronise.")
	}
}

// cmdDirective signs and broadcasts an admin directive:
// `directive <sequence> <expiryBlock> <text>`. It needs the private key of the
// configured AdminKey in the wallet. FIX(H-02, H-03).
func cmdDirective(d *Dispatcher, l string) {
	key := d.N.Options().AdminKey
	var priv string
	for _, w := range d.N.Wallet.All() {
		if key != "" && w.PublicKey == key {
			priv = w.PrivateKey
		}
	}
	if priv == "" {
		d.fail("No private key for the configured AdminKey in this wallet.")
		return
	}
	if !d.needNet() {
		return
	}
	seq, ok1 := codec.StrToInt64(p(l, 1))
	exp, ok2 := codec.StrToInt64(p(l, 2))
	text := codec.Trim(codec.Copy(l, len(p(l, 0))+len(p(l, 1))+len(p(l, 2))+4, len(l)))
	if !ok1 || !ok2 || text == "" {
		d.fail("Syntax: directive {sequence} {expiryBlock} {text}")
		return
	}
	sig := crypto.SignCanonical(priv, "DIRECTIVE1", node.DirectiveFields(seq, exp, text)...)
	d.E.OutgoingAdd(node.PTCHeader(d.N) + "ADMINMSG " + codec.IntToStr(seq) + " " + codec.IntToStr(exp) + " " +
		strings.ReplaceAll(text, " ", "_") + " " + sig)
	d.log("Directive sent: %s", text)
}

// cmdSignCfg signs the current nosocfg text with the wallet key matching
// ConfigKey and stores the signature so the node can serve it:
// `signcfg <sequence>`. FIX(C-01).
func cmdSignCfg(d *Dispatcher, l string) {
	key := d.N.Options().ConfigKey
	for _, w := range d.N.Wallet.All() {
		if key != "" && w.PublicKey == key {
			seq, ok := codec.StrToInt64(p(l, 1))
			if !ok {
				d.fail("Syntax: signcfg {sequence}")
				return
			}
			content := d.N.CFG.DataStr()
			sig := crypto.SignCanonical(w.PrivateKey, "CFG1", node.CFGFields(seq, content)...)
			if err := d.N.AcceptConfig(node.SignedConfig{Seq: seq, Content: content, Sig: sig}); err != nil {
				d.fail("Error: %v", err)
				return
			}
			d.log("Configuration signed with sequence %d", seq)
			return
		}
	}
	d.fail("No private key for the configured ConfigKey in this wallet.")
}

// cmdPost mirrors PostOffer (mpparser.pas:1548-1600): it only validates
// and prints the offer; the exchange feature never publishes anything.
func cmdPost(d *Dispatcher, l string) {
	from := p(l, 1)
	if codec.ASCIIUpper(from) == "DEF" {
		from = d.N.Wallet.At(0).Hash
	}
	var amount int64
	if codec.ASCIIUpper(p(l, 2)) == "MAX" {
		amount = consensus.GetMaximunToSend(d.N.AddressAvailable(from))
	} else {
		amount = codec.StrToInt64Def(p(l, 2), 0)
	}
	market := codec.ASCIIUpper(p(l, 3))
	price := codec.StrToInt64Def(p(l, 4), 0)
	total := amount * price / 100000000
	pay := p(l, 5)
	dur := codec.StrToInt64Def(p(l, 6), 100)
	if dur > 1000 {
		dur = 1000
	}
	tramos := dur / 100
	if dur%100 > 0 {
		tramos++
	}
	fee := consensus.GetMinimumFee(amount) * tramos
	msg := ""
	switch {
	case from == "":
		msg = "post {address} {ammount} {market} {price} {payaddress} {duration}"
	case d.N.Wallet.IndexOf(from) < 0:
		msg = "Invalid Address"
	case amount == 0 || amount+consensus.GetMinimumFee(amount) > d.N.AddressAvailable(from):
		msg = "Invalid Ammount"
	case !strings.Contains("/LTC", market):
		msg = "Invalid market"
	case price <= 0:
		msg = "Invalid price"
	}
	if msg != "" {
		d.log("%s", msg)
		return
	}
	d.log("Post Exchange Offer")
	d.log("From Address: %s", from)
	d.log("Ammount     : %s NOSO", i2c(amount))
	d.log("Market      : %s", market)
	d.log("Price       : %s %s", i2c(price), market)
	d.log("Total       : %s %s", i2c(total), market)
	d.log("Pay to      : %s", pay)
	d.log("Duration    : %d blocks", dur)
	d.log("Fee         : (%d) %s NOSO", tramos, i2c(fee))
}

// cmdTT mirrors DebugTest2: the verificator list.
func cmdTT(d *Dispatcher, l string) {
	e := d.N.MNFile.Entries()
	ver := len(e)/10 + 3
	d.log("%s", d.N.MNFile.VerificatorsText())
	d.log("Masternodes  : %d", len(e))
	d.log("Verificators : %d", ver)
	for i := 0; i < ver && i < len(e); i++ {
		d.log("%s %s %d", e[i].IPAndPort, codec.Copy(e[i].Address, 1, 5), e[i].Age)
	}
}

// seedHTTPClient verifies certificates (the default transport does); tests
// replace it to trust a local server.
var seedHTTPClient = &http.Client{Timeout: 5 * time.Second}

// reloadNodes hands the edited seed list to the running engine (it kept the
// old list until a restart).
func (d *Dispatcher) reloadNodes() {
	if d.E != nil {
		d.E.SetNodesArray(d.N.CFG.Param(1))
	}
}

// cmdPubKey prints the address and public key of one wallet address (the
// first by default), never the private key: this is what goes into the
// proposers file of a network.
func cmdPubKey(d *Dispatcher, l string) {
	i := 0
	if a := p(l, 1); a != "" {
		if i = d.N.Wallet.IndexOf(a); i < 0 {
			d.fail("Address not found in wallet")
			return
		}
	}
	w := d.N.Wallet.At(i)
	d.log("%s %s", w.Hash, w.PublicKey)
}

// cmdWallet: `wallet retire-legacy` removes the clear-text wallet.pkw (and
// its backup) kept after the migration to wallet.enc.
func cmdWallet(d *Dispatcher, l string) {
	switch strings.ToLower(p(l, 1)) {
	case "retire-legacy":
		if err := d.N.Wallet.RetireLegacy(); err != nil {
			d.fail("Not retired: %v", err)
			return
		}
		d.log("The clear-text wallet files were removed.")
	case "":
		said := false
		if w := d.N.Wallet.LegacyWarning(); w != "" {
			d.log("%s", w)
			said = true
		}
		for _, w := range d.N.Wallet.Warnings() {
			d.log("%s", w)
			said = true
		}
		if !said {
			d.log("No clear-text wallet files are left; the keys are in wallet.enc.")
		}
	default:
		d.fail("Syntax: wallet [retire-legacy]")
	}
}

// cmdMNSet: `mnset ip port fundsAddress signAddress` sets the masternode
// options (what `docs/running-a-node.md` asks for) and saves advopt.txt.
func cmdMNSet(d *Dispatcher, l string) {
	ip, port, funds, sign := p(l, 1), p(l, 2), p(l, 3), p(l, 4)
	switch {
	case ip == "" || sign == "" || funds == "":
		d.fail("Syntax: mnset {ip} {port} {funds address} {sign address}")
	case !d.N.ValidMNIP(ip):
		d.fail("Invalid IP")
	case codec.StrToIntDef(port, -1) < 1 || codec.StrToIntDef(port, -1) > 65535:
		d.fail("Invalid port")
	case !crypto.IsValidHashAddress(funds):
		d.fail("Invalid funds address")
	case d.N.Wallet.IndexOf(sign) < 0:
		d.log("The sign address must be an address of this wallet")
	default:
		d.N.UpdateOptions(func(o *node.StorageOptions) { o.MNIP, o.MNPort, o.MNFunds, o.MNSign = ip, port, funds, sign })
		if err := d.N.SaveOptions(); err != nil {
			d.fail("Not saved: %v", err)
			return
		}
		d.log("Masternode set: %s:%s funds %s sign %s", ip, port, funds, sign)
	}
}

// cmdMNDelegate: `mndelegate fundsAddress signAddress`, run where the funds
// key is, prints "fundsPublicKey signature" for `mnsetdelegation` on the
// node that holds the sign key. The private key is never printed.
func cmdMNDelegate(d *Dispatcher, l string) {
	funds, sign := p(l, 1), p(l, 2)
	i := d.N.Wallet.IndexOf(funds)
	if i < 0 || !crypto.IsValidHashAddress(sign) {
		d.fail("Syntax: mndelegate {funds address in this wallet} {sign address}")
		return
	}
	w := d.N.Wallet.At(i)
	if w.PrivateKey == "" {
		d.log("This wallet has no private key for that address")
		return
	}
	d.log("%s %s", w.PublicKey, node.SignDelegation(w.PrivateKey, sign, funds))
}

// cmdMNSetDelegation: `mnsetdelegation fundsPublicKey signature` stores the
// delegation for the configured funds and sign addresses.
func cmdMNSetDelegation(d *Dispatcher, l string) {
	if err := d.N.SetDelegation(p(l, 1), p(l, 2)); err != nil {
		d.log("Delegation refused: %v", err)
		return
	}
	d.log("Delegation stored")
}
