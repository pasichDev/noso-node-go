package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

func p(line string, n int64) string { return codec.Parameter(line, n) }

func i2c(v int64) string { return network.Int2Curr(v) }

func init() {
	handlers = map[string]func(d *Dispatcher, line string){
		"VER":       func(d *Dispatcher, l string) { d.log("%s", node.MainnetVersion+node.NodeRelease) },
		"TIMESTAMP": func(d *Dispatcher, l string) { d.log("%s", d.N.UTCTimeStr()) },
		"OSVERSION": func(d *Dispatcher, l string) { d.log("%s", osVersion()) },
		"CLEAR":     func(d *Dispatcher, l string) {},
		"TP": func(d *Dispatcher, l string) {
			d.log("%s", p(l, 0))
			for i := int64(1); p(l, i) != ""; i++ {
				d.log("%d %s", i, p(l, i))
			}
		},
		"SHA256":     func(d *Dispatcher, l string) { d.log("%s", crypto.SHA256String(p(l, 1))) },
		"MD5":        func(d *Dispatcher, l string) { d.log("%s", crypto.MD5Hex(p(l, 1))) },
		"MD160":      func(d *Dispatcher, l string) { d.log("%s", crypto.RIPEMD160String(p(l, 1))) },
		"BASE58SUM":  func(d *Dispatcher, l string) { d.log("%s", crypto.BMB58resumen(p(l, 1))) },
		"ADDFROMPUB": func(d *Dispatcher, l string) { d.log("%s", crypto.GetAddressFromPublicKey(p(l, 1), 0)) },
		"MYHASH": func(d *Dispatcher, l string) {
			exe, _ := os.Executable()
			d.log("%s", crypto.IDHashFile(exe))
		},
		"STATUS": cmdStatus,
		"SYSTEM": cmdSystem,

		// server / network
		"SERVERON": func(d *Dispatcher, l string) {
			if d.needNet() {
				if err := d.E.StartServerChecked(); err != nil {
					d.log("%s", err.Error())
				}
			}
		},
		"SERVEROFF": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.E.StopServer()
			}
		},
		"FORCESERVER": func(d *Dispatcher, l string) {
			if d.needNet() {
				if d.E.ServerActive() {
					d.log("Server Already active")
				} else if err := d.E.StartServer(int(codec.StrToIntDef(d.N.Options().MNPort, 8080))); err != nil {
					d.fail("Unable to start Server")
				}
			}
		},
		"NODES": func(d *Dispatcher, l string) {
			if d.needNet() {
				for i, nd := range d.E.NodesList() {
					d.log("%d- %s", i, nd)
				}
			}
		},
		"BOTS": func(d *Dispatcher, l string) {
			if d.needNet() {
				b := d.E.Bots()
				for i, ip := range b {
					d.log("%d- %s", i, ip)
				}
				d.log("%d bots registered.", len(b))
			}
		},
		"DELBOTS": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.E.DeleteBots()
			}
		},
		"DISCONNECT": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.E.StopServer() // mpred.pas:413 CloseAllConnections(ServerToo=True)
				for i := 1; i <= network.MaxConnections; i++ {
					if d.E.Peer(i).Tipo == "SER" {
						d.E.CloseSlot(i)
					}
				}
				d.log("Clients connections closed")
			}
		},
		"CONNECTTO": func(d *Dispatcher, l string) {
			if d.needNet() {
				port := p(l, 2)
				if codec.StrToIntDef(port, -1) == -1 {
					port = "8080"
				}
				d.E.ConnectClient(p(l, 1), port)
			}
		},
		"DENYPEER": func(d *Dispatcher, l string) {
			if d.needNet() {
				if hp := p(l, 1); hp == "" {
					d.log("denied: %s", strings.Join(d.E.DeniedPeers(), " "))
				} else {
					d.E.DenyPeer(hp)
					d.log("%s is cut off: connection closed, not dialled, refused", hp)
				}
			}
		},
		"ALLOWPEER": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.E.AllowPeer(p(l, 1))
				d.log("denied: %s", strings.Join(d.E.DeniedPeers(), " "))
			}
		},
		"PUBKEY":          cmdPubKey,
		"MNSET":           cmdMNSet,
		"MNDELEGATE":      cmdMNDelegate,
		"MNSETDELEGATION": cmdMNSetDelegation,
		"WALLET":          cmdWallet,
		"MYIP": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.log("%s", d.E.GetMyIP())
			}
		},
		"PEERS": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.log("Server list: %d/%d", d.E.OutgoingConnections(), d.E.IncomingConnections())
			}
		},
		"AUTOSERVERON": func(d *Dispatcher, l string) {
			d.N.UpdateOptions(func(o *node.StorageOptions) { o.AutoServer = true })
			_ = d.N.SaveOptions()
			d.log("AutoServer option is now ACTIVE")
		},
		"AUTOSERVEROFF": func(d *Dispatcher, l string) {
			d.N.UpdateOptions(func(o *node.StorageOptions) { o.AutoServer = false })
			_ = d.N.SaveOptions()
			d.log("AutoServer option is now INACTIVE")
		},
		"SETPORT":      func(d *Dispatcher, l string) { d.log("Deprecated") },
		"CLOSESTARTON": func(d *Dispatcher, l string) { d.N.UpdateOptions(func(o *node.StorageOptions) { o.CloseStart = true }) },
		"CLOSESTARTOFF": func(d *Dispatcher, l string) {
			d.N.UpdateOptions(func(o *node.StorageOptions) { o.CloseStart = false })
		},
		"SAVEADV": func(d *Dispatcher, l string) {
			if err := d.N.SaveOptions(); err != nil {
				d.fail("Error creating/saving AdvOpt file: %v", err)
			}
		},
		"OFFSET": func(d *Dispatcher, l string) {
			d.log("Time offset seconds: %d", d.N.UTCTime()-time.Now().Unix())
		},
		"USEROPTIONS": func(d *Dispatcher, l string) {
			o := d.N.Options()
			d.log("Language    : %s", o.Language)
			d.log("Server Port : %s", o.MNPort)
			d.log("Wallet      : %s", d.N.Wallet.Path())
			d.log("AutoServer  : %s", boolStr(o.AutoServer))
		},
		"RESTART": func(d *Dispatcher, l string) {
			if d.Quit != nil {
				d.Quit(true)
			} else {
				d.log("This tool cannot restart the daemon; stop and start nosod.")
			}
		},

		// wallet
		"NEWADDRESS": func(d *Dispatcher, l string) {
			if _, err := newWalletAddress(d); err != nil {
				d.fail("Wallet not saved: %v", err)
				return
			}
			d.log("1 new addresses")
		},
		"BALANCE":    func(d *Dispatcher, l string) { d.log("%s NOSO", i2c(walletBalance(d))) },
		"SHOWWALLET": cmdShowWallet,
		"IMPWALLET":  cmdImpWallet,
		"EXPWALLET":  cmdExpWallet,
		"SETDEFAULT": func(d *Dispatcher, l string) { setDefault(d, l) },
		"CUSTOMIZE": func(d *Dispatcher, l string) {
			if d.needNet() && !d.E.Customize(l, d.printer()) {
				d.failed = true
			}
		},
		"SENDTO": cmdSendTo,
		"SENDGVT": func(d *Dispatcher, l string) {
			if d.needNet() && d.E.SendGVT(l, d.printer()) == "" {
				d.failed = true
			}
		},
		"GETCERT": func(d *Dispatcher, l string) {
			addr := p(l, 1)
			i := d.N.Wallet.IndexOf(addr)
			if i < 0 || addr == "" {
				d.fail("Invalid address")
				return
			}
			// FIX(L-05): getcert <address> <audience> <nonce>
			w := d.N.Wallet.At(i)
			cert := crypto.GetCertificate(w.PublicKey, w.PrivateKey, p(l, 2), p(l, 3), d.N.UTCTimeStr())
			if p(l, 2) == "" || p(l, 3) == "" || cert == "" {
				d.fail("Syntax: getcert {address} {audience} {nonce}")
				return
			}
			d.log("%s owner cert: \n%s", addr, cert)
		},
		"CHECKCERT": func(d *Dispatcher, l string) {
			addr, ts := crypto.CheckCertificate(p(l, 1), p(l, 2), p(l, 3))
			if addr == "" {
				d.fail("Invalid verification")
				return
			}
			if al := d.N.Summary.Alias(addr); al != "" {
				addr = fmt.Sprintf("%s [%s]", addr, al)
			}
			t, _ := codec.StrToInt64(ts)
			d.log("%s verified %s ago.", addr, d.N.TimeAgo(t))
		},
		"SHOWKEYS": func(d *Dispatcher, l string) { showKeys(d, l) },
		"EXPKEYS":  func(d *Dispatcher, l string) { showKeys(d, l) },
		"WEBWAL": func(d *Dispatcher, l string) {
			var hs []string
			for _, w := range d.N.Wallet.All() {
				hs = append(hs, w.Hash)
			}
			d.log("%s", strings.Join(hs, ","))
		},
		"EXPORTADDRESS": func(d *Dispatcher, l string) {
			i := d.N.Wallet.IndexOf(p(l, 1))
			if i < 0 {
				d.fail("Address not found in wallet")
				return
			}
			// created exclusively with mode 0600; it holds a private key
			f, err := os.OpenFile("tempwallet.pkw", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				d.fail("Can not create tempwallet.pkw (does it exist already?)")
				return
			}
			_, werr := f.Write(d.N.Wallet.At(i).Encode())
			if f.Close() != nil || werr != nil {
				d.fail("Failed")
				return
			}
			d.log("Address exported to tempwallet.pkw")
			d.log("%s", storage.PKWExportWarning)
		},
		"NEWFROMKEYS": func(d *Dispatcher, l string) {
			var w types.Wallet
			w.PublicKey, w.PrivateKey = p(l, 1), p(l, 2)
			w.Hash = crypto.GetAddressFromPublicKey(w.PublicKey, 0)
			if _, err := d.N.Wallet.Add(w); err != nil {
				d.fail("Wallet not saved: %v", err)
			}
		},
		"GETMULTI": cmdGetMulti,
		"VALIDATE": func(d *Dispatcher, l string) { d.log("%s", boolStr(d.N.Wallet.IndexOf(p(l, 1)) >= 0)) },
		"TESTHASH": func(d *Dispatcher, l string) {
			n := int(codec.StrToIntDef(p(l, 1), 100))
			ok := 0
			for i := 0; i < n; i++ {
				kp := crypto.GenerateKeyPair()
				if crypto.IsValidHashAddress(crypto.GetAddressFromPublicKey(kp.PublicKey, 0)) {
					ok++
				}
			}
			d.log("Correct: %d // Fails : %d ", ok, n-ok)
		},
		"COMPARE": func(d *Dispatcher, l string) {
			k := p(l, 1)
			d.log("Original : %s", crypto.GetAddressFromPublicKey(k, 0))
			d.log("BaseXtoX : %s", crypto.NewGetAddressFromPublicKey(k))
		},

		// chain information
		"RESUMEN": cmdResumen,
		"LBINFO":  func(d *Dispatcher, l string) { showBlockInfo(d, d.N.MyLastBlock()) },
		"BLOCK": func(d *Dispatcher, l string) {
			b := codec.StrToIntDef(p(l, 1), -1)
			if b < 0 || b > d.N.MyLastBlock() {
				d.fail("Invalid block number")
				return
			}
			showBlockInfo(d, b)
		},
		"HALVING": cmdHalving,
		"SUPPLY": func(d *Dispatcher, l string) {
			d.log("Current supply: %s", i2c(consensus.GetSupply(d.N.MyLastBlock())))
		},
		"GETPOS": func(d *Dispatcher, l string) {
			d.log("%d", consensus.GetPoSPercentage(codec.StrToIntDef(p(l, 1), d.N.MyLastBlock())))
		},
		"GETMNS": func(d *Dispatcher, l string) {
			d.log("%d", consensus.GetMNsPercentage(codec.StrToIntDef(p(l, 1), d.N.MyLastBlock()), d.N.CFG.Param(0)))
		},
		"GMTS":     cmdGMTS,
		"HEADSIZE": func(d *Dispatcher, l string) { d.log("%d", d.N.Headers.Height()) },
		"GETDBLB":  func(d *Dispatcher, l string) { d.log("%d", d.N.DB.LastBlock()) },
		"ORDER": func(d *Dispatcher, l string) {
			if !d.needNet() {
				return
			}
			g := d.E.OrderDetails(p(l, 1))
			if g.AmmountTrf <= 0 {
				d.fail("Order not found")
				return
			}
			d.log("Time     : %s", timestampToDate(g.TimeStamp))
			if g.Block == -1 {
				d.log("Block: Pending")
			} else {
				d.log("Block    : %d", g.Block)
			}
			d.log("Type     : %s", g.OrderType)
			d.log("Trfrs    : %d", g.OrderLines)
			d.log("sender   : %s", g.Sender)
			d.log("Receiver : %s", g.Receiver)
			d.log("Ammount  : %s", i2c(g.AmmountTrf))
			d.log("Fee      : %s", i2c(g.AmmountFee))
			d.log("Reference: %s", g.Reference)
		},
		"ORDERSOURCES": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.log("%s", d.E.OrderSources(p(l, 1)))
			}
		},
		"ORDINFO": func(d *Dispatcher, l string) {
			if o, ok := d.N.DB.FindOrder(d.N.Blocks, p(l, 1)); ok {
				d.log("%d", o.Block)
				d.log("%s", o.Sender)
				d.log("%s", o.Receiver)
				d.log("%d", o.AmmountTrf)
			} else {
				d.fail("Order not found")
			}
		},
		"ADDRESS":     cmdAddress,
		"HISTORY":     cmdHistory,
		"TOTALFEES":   cmdTotalFees,
		"BLOCKPOS":    func(d *Dispatcher, l string) { showBlockTail(d, l, true) },
		"BLOCKMNS":    func(d *Dispatcher, l string) { showBlockTail(d, l, false) },
		"SUMARY":      cmdSumary,
		"PENDING":     func(d *Dispatcher, l string) { d.log("%s", network.PendingRawInfo(d.N, true)) },
		"SHOWPENDING": func(d *Dispatcher, l string) {},
		"FUNDS": func(d *Dispatcher, l string) {
			d.log("Project funds \nNpryectdevepmentfundsGE: %s\nNPrjectPrtcRandmJacptE5: %s",
				i2c(d.N.AddressAvailable("NpryectdevepmentfundsGE")), i2c(d.N.AddressAvailable("NPrjectPrtcRandmJacptE5")))
		},
		"LISTGVT": func(d *Dispatcher, l string) {
			gvtInfo(d)
			all := d.N.GVTs.All()
			d.log("Existing: %d", len(all))
			for i, g := range all {
				d.log("%02d %s", i, g.Owner)
			}
		},
		"GVTINFO":      func(d *Dispatcher, l string) { gvtInfo(d) },
		"FREEZED":      cmdFreezed,
		"SUMINDEXSIZE": func(d *Dispatcher, l string) { d.log("%d", d.N.Summary.Len()) },
		"MNSCHECKS": func(d *Dispatcher, l string) {
			cs := d.N.Checks()
			for _, c := range cs {
				d.log("%s,%d", c.ValidatorIP, node.ValidNodesInCheck(c.ValidNodes))
			}
			if len(cs) == 0 {
				d.log("No masternode checks in this block yet.")
			}
		},
		"CONSENSUS": cmdConsensus,
		"CONSTATS": func(d *Dispatcher, l string) {
			if d.needNet() {
				d.log("%s %s", d.E.GetConsensus(8), codec.Copy(d.N.MNFile.Hash(), 1, 5))
				d.N.Wallet.ImportFromBackup(d.N.Lay.RPCBakDir)
			}
		},
		"ISALLSYNCED": func(d *Dispatcher, l string) { d.log("%d", d.N.IsAllSynced()) },
		"NOSOCFG":     func(d *Dispatcher, l string) { d.log("%s", d.N.CFG.DataStr()) },

		// maintenance
		"UNDOBLOCK": func(d *Dispatcher, l string) { d.N.UndoLastBlock() },
		"REBUILDSUM": func(d *Dispatcher, l string) {
			if err := d.N.RebuildSummary(); err != nil {
				d.log("rebuild failed, previous state restored: %v", err)
			}
		},
		"ZIPSUMARY":         func(d *Dispatcher, l string) { _ = d.N.ZipSummary() },
		"RESTORESUMARY":     func(d *Dispatcher, l string) { restoreSummary(d) },
		"RESTOREBLOCKCHAIN": cmdRestoreChain,
		"TESTHEAD": func(d *Dispatcher, l string) {
			raw, _ := d.N.Headers.Bytes()
			d.log("File size: %d", len(raw))
			d.N.Headers.Replace(raw)
			d.N.UpdateMyData()
		},

		// configuration (nosocfg)
		"SETMODE":    func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.SetData(p(l, 1), 0)) },
		"ADDNODE":    func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Add(p(l, 1), 1)); d.reloadNodes() },
		"DELNODE":    func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Remove(p(l, 1), 1)); d.reloadNodes() },
		"ADDPOOL":    func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Add(p(l, 1), 3)) },
		"DELPOOL":    func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Remove(p(l, 1), 3)) },
		"ADDNOSOPAY": func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Add(p(l, 1), 6)) },
		"DELNOSOPAY": func(d *Dispatcher, l string) { cfgErr(d, d.N.CFG.Remove(p(l, 1), 6)) },
		"RESTORECFG": cmdRestoreCFG,
		"CLEARCFG":   func(d *Dispatcher, l string) { d.N.CFG.Clear(p(l, 1)); d.reloadNodes() },
		"DIRECTIVE":  cmdDirective,
		"SIGNCFG":    cmdSignCfg,

		// RPC
		"SETRPCPORT": func(d *Dispatcher, l string) {
			v := codec.StrToIntDef(p(l, 1), 0)
			switch {
			case v <= 0 || v > 65535:
				d.fail("Invalid value")
			case d.R != nil && d.R.Active():
				d.fail("Can not change the RPC port when it is active")
			default:
				d.N.UpdateOptions(func(o *node.StorageOptions) { o.RPCPort = int(v) })
				_ = d.N.SaveOptions()
				d.log("RPC port set to: %d", v)
			}
		},
		"RPCON": func(d *Dispatcher, l string) {
			if d.R == nil {
				d.needNet()
				return
			}
			if err := d.R.Start(d.N.Options().RPCPort); err != nil {
				if d.R.Active() {
					d.log("RPC server already ENABLED")
				} else {
					d.fail("Unable to start RPC port")
				}
				return
			}
			d.log("RPC server ENABLED")
		},
		"RPCOFF": func(d *Dispatcher, l string) {
			if d.R == nil {
				d.needNet()
				return
			}
			if d.R.Active() {
				d.R.Stop()
				d.log("RPC server DISABLED")
			} else {
				d.log("RPC server already DISABLED")
			}
		},

		// PSOs
		// FIX(GAP-5): the PSO file is part of the state root, so a PSO is never
		// changed on one node. newpso and clearpsos sign an order, which a
		// proposer mines into a block; every node applies it there.
		"NEWPSO": cmdNewPSO,
		"LISTPSOS": func(d *Dispatcher, l string) {
			h := d.N.PSOs.Header()
			d.log("PSOSs list")
			d.log("Block: %d", h.Block)
			d.log("MNs  : %d", h.MNsLock)
			d.log("PSOs : %d", h.Count)
			for _, x := range d.N.PSOs.All() {
				d.log("%d,%s,%s,%d,%s", x.Mode, x.Hash, x.Owner, x.Expire, x.Params)
			}
		},
		"CLEARPSOS": cmdClearPSOs,
		"SHOWPSOS": func(d *Dispatcher, l string) {
			for i := 0; i < d.N.PSOs.LockedCount(); i++ {
				m := d.N.PSOs.LockedAt(i)
				d.log("%s %d", m.Address, m.Expire)
			}
		},

		// repository seeds
		"GETREPOSEEDS": func(d *Dispatcher, l string) {
			d.log("%s", FetchSeeds(p(l, 1), d.N.Options().ReleaseKey))
		},
		"FORCEREPOSEEDS": func(d *Dispatcher, l string) {
			if list := FetchSeeds(p(l, 1), d.N.Options().ReleaseKey); list != "" {
				cfgErr(d, d.N.CFG.SetData(list, 1))
			} else {
				d.fail("No verified seed list (needs https url and a configured ReleaseKey).")
			}
		},

		// FIX(C-08): update, getbeta, checkupdates, sendreport and testnet do not
		// exist: no code is ever downloaded or run, no report is uploaded.
		"POST": cmdPost,
		"TT":   cmdTT,
	}
}

// cmdSendTo: sendto {destination} {amount} {reference}. The amount is in NOSO
// ("10", "1.5", "0.00000001"); a trailing u gives base units ("150000000u").
// The RPC method sendfunds takes base units only.
func cmdSendTo(d *Dispatcher, l string) {
	if !d.needNet() {
		return
	}
	amount := p(l, 2)
	if amount != "" {
		units, err := network.ParseAmount(amount)
		if err != nil {
			d.fail("Invalid ammount: %v.", err)
			d.log("Syntax: sendto {destination} {ammount in NOSO, for example 1.5} {reference}; 150000000u gives base units (1 NOSO = 100000000).")
			return
		}
		l = "sendto " + p(l, 1) + " " + codec.IntToStr(units) + " " + p(l, 3)
	}
	if res := d.E.SendFunds(l, d.printer(), 0); res == "" || strings.HasPrefix(res, "ERROR") {
		d.failed = true
	}
}

// cmdNewPSO: newpso [mode] [params] [address]. Without arguments it sends the
// test PSO of the original command (mode 1, the time, the last block, action 1,
// fee 500, duration 2016) for the first wallet address. The PSO exists once a
// block holds the order.
func cmdNewPSO(d *Dispatcher, l string) {
	if !d.needNet() {
		return
	}
	mode, params, addr := int64(1), "", p(l, 3)
	if m := p(l, 1); m != "" {
		v, ok := codec.StrToInt64(m)
		if !ok || v < 1 || v > 65535 {
			d.fail("Syntax: newpso [mode 1..65535] [params label:value;...] [address]")
			return
		}
		mode = v
	}
	params = p(l, 2)
	if params == "" {
		params = "1:" + d.N.UTCTimeStr() + ";2:" + codec.IntToStr(d.N.MyLastBlock()) + ";3:1;4:500;5:2016;"
	}
	if addr == "" {
		addr = d.N.Wallet.At(0).Hash
	}
	if !d.E.NewPSO(addr, int(mode), params, d.printer()) {
		d.failed = true
	}
}

// cmdClearPSOs: clearpsos [address] removes the PSOs of an address of this
// wallet (the first by default) with a signed order; other owners' PSOs stay.
func cmdClearPSOs(d *Dispatcher, l string) {
	if !d.needNet() {
		return
	}
	addr := p(l, 1)
	if addr == "" {
		addr = d.N.Wallet.At(0).Hash
	}
	if !d.E.ClearPSOs(addr, d.printer()) {
		d.failed = true
	}
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func cfgErr(d *Dispatcher, err error) {
	if err != nil {
		d.fail("Error: %v", err)
	}
}

func osVersion() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "Mac OS X 10."
	}
	return "Linux Kernel "
}

func timestampToDate(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("02/01/2006 15:04:05")
}

// cmdRestoreCFG puts the defaults back for everything except the seed list.
// FIX: it used to reset the seeds too, and this port ships no default seeds,
// so the node went to zero peers without a word. `restorecfg seeds` does the
// full reset on purpose.
func cmdRestoreCFG(d *Dispatcher, l string) {
	all := strings.EqualFold(p(l, 1), "seeds")
	seeds := d.N.CFG.Param(1)
	d.N.CFG.Restore()
	if !all {
		cfgErr(d, d.N.CFG.SetData(seeds, 1))
		d.log("Configuration restored to the defaults. The seed list was kept: %s", strings.TrimSpace(strings.ReplaceAll(seeds, ":", " ")))
	} else {
		d.log("Configuration and seed list restored to the defaults. This build has no default seeds: " +
			"the node has no peers to connect to until you set some (init-network -seed, or the directive/seed-url).")
	}
	d.reloadNodes()
}
