//go:build gui

package ui

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// amountUnits converts "12.345" to 1234500000 (8 decimals); ok is false for
// anything but digits with at most one point and 8 decimals.
func amountUnits(s string) (int64, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 2 || parts[0] == "" && len(parts) == 1 {
		return 0, false
	}
	dec := ""
	if len(parts) == 2 {
		dec = parts[1]
	}
	if len(dec) > 8 {
		return 0, false
	}
	dec += strings.Repeat("0", 8-len(dec))
	v, ok := codec.StrToInt64(parts[0] + dec)
	for _, c := range parts[0] + dec {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	return v, ok && v > 0
}

// ---- Wallet tab: addresses, customize, send (TabAddresses, PanelSend) --------

func (a *App) walletTab() fyne.CanvasObject {
	a.balance = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	a.addrList = grid(func() [][]string { return a.addrRows }, 520, 160)
	selected := -1
	a.addrList.OnSelected = func(id widget.TableCellID) { selected = id.Row; a.selAddr = id.Row }
	addr := func() string {
		if selected < 0 || selected >= len(a.addrRows) {
			return ""
		}
		return strings.TrimSuffix(a.addrRows[selected][0], " [MN]")
	}

	// BDefAddr, BCustomAddr, BCopyAddr, BNewAddr
	def := widget.NewButton("Set default", func() {
		if x := addr(); x != "" {
			a.runCommand("SETDEFAULT " + x)
		}
	})
	custom := widget.NewButton("Customize...", func() {
		x := addr()
		if x == "" {
			return
		}
		// BCustomAddrOnClick checks (masterpaskalform.pas:2864-2880)
		switch {
		case !crypto.IsValidHashAddress(x), a.n.AddressAlreadyCustomized(x):
			a.info("Address already customized")
			return
		case a.n.AddressAvailable(x) < consensus.GetCustFee(a.n.MyLastBlock()):
			a.info("Insufficient funds")
			return
		}
		e := widget.NewEntry()
		e.SetPlaceHolder("alias (5-40 characters)")
		dlg := widget.NewForm(widget.NewFormItem("Alias", e))
		fdialog(a, "Customize "+x, dlg, func() { a.runCommand("Customize " + x + " " + e.Text) })
	})
	cp := widget.NewButton("Copy", func() {
		if x := addr(); x != "" {
			a.win.Clipboard().SetContent(x)
			a.info("Copied to clipboard")
		}
	})
	newAddr := widget.NewButton("New address", func() { a.runCommand("newaddress") })

	// send panel
	dest := widget.NewEntry()
	dest.SetPlaceHolder("destination address or alias")
	amount := widget.NewEntry()
	amount.SetText("0.00000000")
	ref := widget.NewEntry()
	ref.SetPlaceHolder("reference")
	destOK := widget.NewLabel("")
	dest.OnChanged = func(s string) {
		clean := strings.ReplaceAll(s, " ", "")
		if clean != s {
			dest.SetText(clean)
			return
		}
		switch {
		case s == "":
			destOK.SetText("")
		case crypto.IsValidHashAddress(s) || a.n.AliasAlreadyExists(s):
			destOK.SetText("✓")
		default:
			destOK.SetText("✗")
		}
	}
	amountOK := widget.NewLabel("")
	amount.OnChanged = func(s string) {
		if v, ok := amountUnits(s); ok && v <= consensus.GetMaximunToSend(a.e.WalletBalance()) {
			amountOK.SetText("✓")
		} else if s == "0.00000000" {
			amountOK.SetText("")
		} else {
			amountOK.SetText("✗")
		}
	}
	paste := widget.NewButton("Paste", func() { dest.SetText(strings.ReplaceAll(a.win.Clipboard().Content(), " ", "")) })
	maxBtn := widget.NewButton("Max", func() { // SBSCMaxOnClick
		o := a.n.Options()
		bal := a.e.WalletBalance()
		if o.MultiSend {
			bal = a.n.Summary.BalanceIndexed(a.n.Wallet.At(0).Hash)
		}
		amount.SetText(network.Int2Curr(consensus.GetMaximunToSend(bal)))
	})
	var send, conf, cancel *widget.Button
	set := func(confirming bool) {
		for _, w := range []fyne.Disableable{dest, amount, ref} {
			if confirming {
				w.Disable()
			} else {
				w.Enable()
			}
		}
		if confirming {
			send.Hide()
			conf.Show()
			cancel.Show()
		} else {
			send.Show()
			conf.Hide()
			cancel.Hide()
		}
	}
	send = widget.NewButton("Send", func() { // SCBitSendOnClick
		v, ok := amountUnits(amount.Text)
		if (crypto.IsValidHashAddress(dest.Text) || a.n.AliasAlreadyExists(dest.Text)) && ok &&
			v <= consensus.GetMaximunToSend(a.e.WalletBalance()) {
			ref.SetText(codec.Parameter(ref.Text, 0))
			set(true)
		} else {
			a.info("Invalid parameters")
		}
	})
	conf = widget.NewButton("Confirm", func() { // SCBitConfOnClick
		v, _ := amountUnits(amount.Text)
		line := fmt.Sprintf("SENDTO %s %d %s", dest.Text, v, ref.Text)
		a.appendLog("console", ">> "+line)
		start := a.selAddr - 1 // the original starts at the selected row
		if start < 0 {
			start = 0
		}
		go a.e.SendFunds(line, func(s string) { a.appendLog("console", s) }, start)
		dest.SetText("")
		amount.SetText("0.00000000")
		ref.SetText("")
		set(false)
	})
	cancel = widget.NewButton("Cancel", func() { set(false) })
	conf.Hide()
	cancel.Hide()
	a.donate = func() {
		dest.SetText(consensus.ProjectFunds)
		amount.SetText("10.00000000")
		ref.SetText("Donation")
	}

	left := container.NewBorder(container.NewVBox(a.balance, container.NewHBox(def, custom, cp, newAddr)), nil, nil, nil, a.addrList)
	form := container.NewVBox(
		widget.NewLabelWithStyle("Send", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, widget.NewLabel("Destination"), container.NewHBox(destOK, paste), dest),
		container.NewBorder(nil, nil, widget.NewLabel("Amount"), container.NewHBox(amountOK, maxBtn), amount),
		container.NewBorder(nil, nil, widget.NewLabel("Reference"), nil, ref),
		container.NewHBox(send, conf, cancel))
	return container.NewHSplit(left, form)
}

// fdialog shows a small OK/Cancel form.
func fdialog(a *App, title string, content fyne.CanvasObject, ok func()) {
	d := newFormDialog(title, content, ok, a.win)
	d.Show()
}

// ---- Console tab (TabConsole, ConsoleLine and its popups) --------------------

type cmdEntry struct {
	widget.Entry
	a *App
}

func (c *cmdEntry) TypedKey(k *fyne.KeyEvent) {
	switch k.Name {
	case fyne.KeyF3, fyne.KeyUp: // F3 recalls the last command
		c.SetText(c.a.lastCmd)
		c.CursorColumn = len(c.Text)
	case fyne.KeyEscape:
		c.SetText("")
	default:
		c.Entry.TypedKey(k)
	}
}

func (a *App) consoleTab() fyne.CanvasObject {
	a.console = widget.NewMultiLineEntry()
	a.console.Wrapping = fyne.TextWrapWord
	a.console.Disable()
	in := &cmdEntry{a: a}
	in.ExtendBaseWidget(in)
	in.SetPlaceHolder("command (F3: repeat last, Esc: clear)")
	in.OnSubmitted = func(s string) { // ConsoleLineKeyup VK_RETURN
		in.SetText("")
		if s == "" {
			return
		}
		a.lastCmd = s
		go a.runCommand(s)
	}
	clear := widget.NewButton("Clear", func() { // ConsolePopUpClear
		a.mu.Lock()
		a.consoleBuf = nil
		a.mu.Unlock()
		a.console.SetText("")
	})
	cp := widget.NewButton("Copy", func() { a.win.Clipboard().SetContent(a.console.Text) }) // ConsolePopUpCopy
	paste := widget.NewButton("Paste", func() { in.SetText(in.Text + a.win.Clipboard().Content()) })
	return container.NewBorder(nil, container.NewBorder(nil, nil, nil, container.NewHBox(paste, cp, clear), in), nil, nil,
		container.NewVScroll(a.console))
}

// ---- Monitor tab (TabMonitor: data panel, connections, consensus, logs) ------

func (a *App) monitorTab() fyne.CanvasObject {
	a.dataGrid = grid(func() [][]string { return a.dataRows }, 120, 160, 120, 160)
	a.slotsGrid = grid(func() [][]string { return a.slotRows }, 50, 50, 140, 90, 80, 70, 90, 70, 60)
	a.consGrid = grid(func() [][]string { return a.consRows }, 40, 130, 520)
	a.eventsLog = widget.NewMultiLineEntry()
	a.eventsLog.Disable()
	a.excepLog = widget.NewMultiLineEntry()
	a.excepLog.Disable()
	clearEv := widget.NewButton("Clear", func() { a.mu.Lock(); a.eventsBuf = nil; a.mu.Unlock(); a.eventsLog.SetText("") })
	clearEx := widget.NewButton("Clear", func() { a.mu.Lock(); a.exceptsBuf = nil; a.mu.Unlock(); a.excepLog.SetText("") })
	procs := widget.NewLabel("")
	go func() {}() // processes tab is informational
	updateProcs := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		procs.SetText(fmt.Sprintf("Goroutines: %d\nMemory in use: %d MB\nThe original shows its Pascal thread and file-transfer tables here; "+
			"goroutines replace threads and transfers are logged in Events.", runtime.NumGoroutine(), m.HeapInuse/1048576))
	}
	updateProcs()
	return container.NewAppTabs(
		container.NewTabItem("Data", a.dataGrid),
		container.NewTabItem("Connections", a.slotsGrid),
		container.NewTabItem("Consensus", a.consGrid),
		container.NewTabItem("Events", container.NewBorder(nil, clearEv, nil, nil, a.eventsLog)),
		container.NewTabItem("Exceptions", container.NewBorder(nil, clearEx, nil, nil, a.excepLog)),
		container.NewTabItem("Processes", container.NewVBox(procs, widget.NewButton("Refresh", updateProcs))),
	)
}

// ---- Masternodes tab (TabNodes, GridNodes) ---------------------------------

func (a *App) mnTab() fyne.CanvasObject {
	a.mnGrid = grid(func() [][]string { return a.mnRows }, 260, 300, 80)
	return a.mnGrid
}

// ---- GVTs tab (TabGVTs, PanelTransferGVT) ------------------------------------

func (a *App) gvtTab() fyne.CanvasObject {
	a.gvtGrid = grid(func() [][]string { return a.gvtRows }, 50, 520)
	sel := -1
	a.gvtGrid.OnSelected = func(id widget.TableCellID) { sel = id.Row - 1 }
	dest := widget.NewEntry()
	dest.SetPlaceHolder("destination address or alias")
	info := widget.NewLabel("")
	send := widget.NewButton("Transfer selected GVT", func() {
		if sel < 0 || dest.Text == "" {
			a.info("Select a GVT and a destination")
			return
		}
		a.runCommand(fmt.Sprintf("SENDGVT %d %s", sel, dest.Text))
	})
	upd := func() {
		av := a.n.GVTs.CountAvailable()
		info.SetText(fmt.Sprintf("Available: %d   Buy: %s   Sell: %s", av,
			network.Int2Curr(gvtPrice(av, false)), network.Int2Curr(gvtPrice(av, true))))
	}
	upd()
	return container.NewBorder(container.NewVBox(info, container.NewBorder(nil, nil, nil, send, dest)), nil, nil, nil, a.gvtGrid)
}

// ---- Options tab (tabOptions) ----------------------------------------------

func (a *App) optionsTab() fyne.CanvasObject {
	o := a.n.Options()
	save := func(f func(op *node.StorageOptions)) { a.n.UpdateOptions(f); _ = a.n.SaveOptions() }
	check := func(label string, v bool, f func(op *node.StorageOptions, b bool)) *widget.Check {
		c := widget.NewCheck(label, func(b bool) { save(func(op *node.StorageOptions) { f(op, b) }) })
		c.SetChecked(v)
		return c
	}
	wallet := container.NewVBox(
		check("Hide empty addresses", o.HideEmpty, func(op *node.StorageOptions, b bool) { op.HideEmpty = b }),
		check("Use all addresses to send funds", o.MultiSend, func(op *node.StorageOptions, b bool) { op.MultiSend = b }),
		check("Keep a blocks database (order lookup)", o.BlocksDB, func(op *node.StorageOptions, b bool) { op.BlocksDB = b }),
		check("No GUI refresh (headless)", o.NoGUI, func(op *node.StorageOptions, b bool) { op.NoGUI = b }),
		widget.NewLabel("Automatic updates and bug reports to the developers do not exist in this implementation."),
	)

	ip := widget.NewEntry()
	ip.SetText(o.MNIP)
	port := widget.NewEntry()
	port.SetText(o.MNPort)
	funds := widget.NewEntry()
	funds.SetText(o.MNFunds)
	sign := widget.NewEntry()
	sign.SetText(o.MNSign)
	autoIP := widget.NewCheck("Automatic IP", nil)
	autoIP.SetChecked(o.MNAutoIP)
	autoSrv := widget.NewCheck("Start the node server automatically", nil)
	autoSrv.SetChecked(o.AutoServer)
	build := widget.NewCheck("This node proposes blocks", nil)
	build.SetChecked(o.BuildBlocks)
	saveNode := widget.NewButton("Save", func() { // BSaveNodeOptionsClick
		save(func(op *node.StorageOptions) {
			op.AutoServer, op.MNIP, op.MNPort = autoSrv.Checked, strings.TrimSpace(ip.Text), strings.TrimSpace(port.Text)
			op.MNFunds, op.MNSign, op.MNAutoIP, op.BuildBlocks = strings.TrimSpace(funds.Text), strings.TrimSpace(sign.Text), autoIP.Checked, build.Checked
		})
		if !autoSrv.Checked && a.e.ServerActive() {
			a.runCommand("serveroff")
		}
		if autoSrv.Checked && !a.e.ServerActive() {
			a.runCommand("serveron")
		}
		a.info("Masternode options saved")
	})
	test := widget.NewButton("Test node", func() { go a.testNode(ip.Text, port.Text, funds.Text, sign.Text, autoIP.Checked) }) // BTestNodeClick
	nodeTab := container.NewVBox(
		widget.NewForm(widget.NewFormItem("IP", ip), widget.NewFormItem("Port", port),
			widget.NewFormItem("Funds address", funds), widget.NewFormItem("Sign address", sign)),
		autoIP, autoSrv, build, container.NewHBox(saveNode, test))

	rport := widget.NewEntry()
	rport.SetText(fmt.Sprint(o.RPCPort))
	rport.OnSubmitted = func(s string) { a.runCommand("SETRPCPORT " + s); rport.SetText(fmt.Sprint(a.n.Options().RPCPort)) }
	tokenRead := widget.NewEntry()
	tokenRead.SetText(o.RPCToken)
	tokenRead.Disable()
	tokenSpend := widget.NewPasswordEntry()
	tokenSpend.SetText(o.RPCSpendToken)
	tokenSpend.Disable()
	wl := widget.NewEntry()
	wl.SetText(o.RPCWhitelist)
	wl.OnSubmitted = func(s string) {
		save(func(op *node.StorageOptions) { op.RPCWhitelist = codec.Parameter(strings.TrimSpace(s), 0) })
	}
	banned := widget.NewEntry()
	banned.SetText(o.RPCBanned)
	banned.OnSubmitted = func(s string) { save(func(op *node.StorageOptions) { op.RPCBanned = s }) }
	rpcTab := container.NewVBox(
		widget.NewForm(widget.NewFormItem("Port", rport), widget.NewFormItem("Read token", tokenRead),
			widget.NewFormItem("Spend token", tokenSpend), widget.NewFormItem("Whitelisted IPs", wl),
			widget.NewFormItem("Banned methods", banned)),
		check("Enable the RPC server at start", o.RPCAuto, func(op *node.StorageOptions, b bool) { op.RPCAuto = b }),
		check("Filter by IP whitelist", o.RPCFilter, func(op *node.StorageOptions, b bool) { op.RPCFilter = b }),
		check("Save new addresses created by RPC", o.RPCSaveNew, func(op *node.StorageOptions, b bool) { op.RPCSaveNew = b }),
		container.NewHBox(widget.NewButton("Start RPC", func() { a.runCommand("rpcon") }),
			widget.NewButton("Stop RPC", func() { a.runCommand("rpcoff") })))

	web := widget.NewButton("Project page", func() { // BitBtnWebClick
		u, _ := url.Parse("https://github.com/nosocoin/NosoNode")
		_ = a.fa.OpenURL(u)
	})
	donate := widget.NewButton("Donate", func() { a.donate() }) // BitBtnDonateClick (prefills the send panel)
	about := container.NewVBox(
		widget.NewLabel("Noso project: Brought to you by the Noso Team (original).\nThis is an independent, unofficial Go port."),
		widget.NewLabel(fmt.Sprintf("Version %s%s  Protocol %d  %s", node.MainnetVersion, node.NodeRelease, node.Protocol, node.BuildDate)),
		container.NewHBox(web, donate))
	return container.NewAppTabs(
		container.NewTabItem("Wallet", wallet), container.NewTabItem("Node", nodeTab),
		container.NewTabItem("RPC", rpcTab), container.NewTabItem("About", about))
}

// testNode mirrors BTestNodeClick: it opens the server briefly and asks the
// configured address for NODESTATUS.
func (a *App) testNode(ip, port, funds, sign string, auto bool) {
	switch {
	case a.n.Wallet.IndexOf(sign) < 0:
		a.info("Sign address not valid")
		return
	case a.n.Summary.BalanceIndexed(funds) < consensus.GetStackRequired(a.n.MyLastBlock()):
		a.info("Funds address do not owns enough coins")
		return
	case a.e.ServerActive():
		a.info("You can not test while server is active")
		return
	case a.n.ConStatus() < 3:
		a.info("You need update the wallet")
		return
	}
	if err := a.e.StartServer(int(codec.StrToIntDef(port, 8080))); err != nil {
		a.info("Error activating server: " + err.Error())
		return
	}
	defer a.e.StopServer()
	target := strings.TrimSpace(ip)
	if auto {
		target = a.e.GetMyIP()
	}
	if got := a.e.RequestLine(target, int(codec.StrToIntDef(strings.TrimSpace(port), 8080)), "NODESTATUS"); got != "" {
		a.info(target + ": OK")
	} else {
		a.info("Test Failed: " + target)
	}
}
