//go:build gui

// Package ui is the Fyne user interface. Each screen mirrors a part of the
// original Lazarus form (masterpaskalform.lfm); docs/port-status.md lists
// them one by one.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/logx"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/rpc"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// App ties the windows to a running node.
type App struct {
	fa  fyne.App
	win fyne.Window

	n *node.Node
	e *network.Engine
	r *rpc.Server
	d *cli.Dispatcher

	dataDir string
	lock    *storage.DirLock // exclusive hold on the data directory for the life of the window
	ctl     *control.Server  // control socket, so nosocli talks to this node instead of opening the files

	mu         sync.Mutex
	consoleBuf []string
	eventsBuf  []string
	exceptsBuf []string
	lastCmd    string

	// widgets updated by the refresh loop
	status    *widget.Label
	infoLabel *widget.Label
	balance   *widget.Label
	addrList  *widget.Table
	dataGrid  *widget.Table
	slotsGrid *widget.Table
	consGrid  *widget.Table
	mnGrid    *widget.Table
	gvtGrid   *widget.Table
	console   *widget.Entry
	eventsLog *widget.Entry
	excepLog  *widget.Entry

	tabs    *container.AppTabs
	monTabs *container.AppTabs
	optTabs *container.AppTabs
	// widgets the tests drive
	sendDest, sendAmount *widget.Entry
	sendBtn, confBtn     *widget.Button
	consoleIn            *widget.Entry
	hideCheck            *widget.Check
	headless             bool          // tests: no peer-to-peer engine, no NTP
	done                 chan struct{} // closed by shutdown; stops the refresh loop
	closing              sync.Once

	donate   func()
	selAddr  string // hash of the selected wallet address
	selGVT   int
	dataRows [][]string
	slotRows [][]string
	consRows [][]string
	mnRows   [][]string
	gvtRows  [][]string
	addrRows [][]string
}

// Run starts the application: passphrase prompt, node start, main window.
func Run() {
	dir := os.Getenv("NOSO_DATA")
	if dir == "" {
		dir = "NOSODATA"
	}
	a := newApp(app.NewWithID("io.github.pasichdev.noso-node-go"), dir)
	a.showStartup()
	// Unattended start (used for automated checks): the passphrase comes from
	// the environment and the initial tab from NOSO_GUI_TAB.
	if p := os.Getenv("NOSO_WALLET_PASSPHRASE"); p != "" {
		go func() {
			if err := a.startNode([]byte(p), false, func(string) {}); err == nil {
				fyne.Do(func() { a.buildMain() })
			}
		}()
	}
	a.win.ShowAndRun()
}

// newApp creates the application object and its window on fa.
func newApp(fa fyne.App, dataDir string) *App {
	a := &App{fa: fa, dataDir: dataDir, done: make(chan struct{})}
	a.win = fa.NewWindow("Noso " + node.MainnetVersion + node.NodeRelease)
	a.win.Resize(fyne.NewSize(1000, 680))
	return a
}

// showStartup mirrors FormInicio: a progress list and the wallet passphrase.
func (a *App) showStartup() {
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("wallet passphrase")
	list := widget.NewMultiLineEntry()
	list.Disable()
	plain := widget.NewCheck("use an unencrypted wallet (not recommended)", nil)
	start := widget.NewButton("Start", nil)
	step := func(s string) { fyne.Do(func() { list.SetText(list.Text + s + "\n") }) }
	start.OnTapped = func() {
		start.Disable()
		typed := []byte(pass.Text)
		pass.SetText("") // FIX(G6): the passphrase does not stay in the entry
		go func() {
			if err := a.startNode(typed, plain.Checked, step); err != nil {
				step("x " + err.Error())
				fyne.Do(func() { start.Enable() })
				return
			}
			fyne.Do(func() { a.buildMain() })
		}()
	}
	a.win.SetContent(container.NewBorder(
		container.NewVBox(widget.NewLabel("Noso "+node.MainnetVersion+node.NodeRelease+" - unofficial Go port"),
			pass, plain, start), nil, nil, nil, list))
}

// startNode mirrors StartProgram (masterpaskalform.pas:1648-1742).
func (a *App) startNode(pass []byte, plain bool, step func(string)) error {
	step("Opening data directory " + a.dataDir)
	// FIX(C3, G1): one process owns the data directory; nosocli beside the GUI
	// is refused (or, through the control socket below, served by this node).
	lock, err := storage.LockDataDir(a.dataDir)
	if err != nil {
		return err
	}
	if err := cli.CheckNewPassphrase(a.dataDir, pass); err != nil { // finding 20
		_ = lock.Close()
		return err
	}
	n, err := node.NewWithConfig(a.dataDir, node.Config{WalletPassphrase: pass, InsecurePlainWallet: plain})
	if err != nil {
		_ = lock.Close()
		return err
	}
	a.lock = lock
	step("✓ Files tree ok")
	step("✓ Wallet, summary, headers, masternodes and GVTs files ok")
	n.EnsureRPCTokens()
	lim := &logx.Limiter{Rate: 200}
	logf := func(ch, msg string) {
		if !lim.Allow() {
			return
		}
		a.appendLog(ch, logx.Sanitize(msg))
	}
	n.Log = logf
	e := network.NewEngine(n)
	e.Log = logf
	e.BindAddr = network.ReadBind(a.dataDir) // same rule as nosod: bind.txt is obeyed
	a.n, a.e = n, e
	a.r = rpc.New(e)
	a.r.Log = logf
	a.d = cli.New(n, e, a.r)
	a.d.Echo = true
	// The GUI cannot restart itself without re-executing a binary, which
	// this implementation never does (C-08). A restart request is answered
	// in the console and the RPC method is not offered.
	a.d.Quit = func(restart bool) {
		if restart {
			a.appendLog("console", "The GUI cannot restart itself: close it and start it again.")
			return
		}
		fyne.Do(func() { a.shutdown() })
	}
	a.r.Restart = nil
	if w := n.Wallet.LegacyWarning(); w != "" {
		a.appendLog("console", w)
	}
	for _, w := range n.Wallet.Warnings() {
		a.appendLog("console", w)
	}
	if ctl, err := control.Serve(control.SocketPath(a.dataDir), a.d.ControlRunner(pass)); err == nil {
		a.ctl = ctl
	} else {
		a.appendLog("console", "control socket unavailable: "+err.Error())
	}
	step("✓ GUI initialized")
	if !a.headless {
		e.UpdateTimeOffset(n.CFG.Param(2))
		step("✓ Mainnet time synced")
		go a.ntpLoop()
		e.Start()
	}
	step("Noso is ready")
	o := n.Options()
	if o.RPCAuto {
		_ = a.r.Start(o.RPCPort)
	}
	return nil
}

// ntpLoop refreshes the clock offset every period, like nosod.
func (a *App) ntpLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
			a.e.UpdateTimeOffset(a.n.CFG.Param(2))
		}
	}
}

func (a *App) appendLog(ch, msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	line := time.Now().Format("15:04:05 ") + msg
	switch ch {
	case "events":
		a.eventsBuf = trimBuf(append(a.eventsBuf, line))
	case "exceps":
		a.exceptsBuf = trimBuf(append(a.exceptsBuf, line))
	default:
		a.consoleBuf = trimBuf(append(a.consoleBuf, msg))
	}
}

func trimBuf(b []string) []string {
	if len(b) > 1000 {
		b = b[len(b)-1000:]
	}
	return b
}

// runCommand executes a console line through the shared dispatcher and
// shows its output in the console tab (ProcessLinesAdd).
func (a *App) runCommand(line string) {
	if cli.Sensitive(line) {
		// FIX(G6): key material is shown once, in a window of its own, and
		// never enters the console buffer (which Copy and Clear operate on).
		var out []string
		a.d.RunTo(line, func(s string) { out = append(out, s) })
		fyne.Do(func() { dialog.ShowInformation("Output of a sensitive command", strings.Join(out, "\n"), a.win) })
		return
	}
	a.d.RunTo(line, func(s string) { a.appendLog("console", s) })
}

func (a *App) info(s string) {
	fyne.Do(func() { a.infoLabel.SetText(s) })
	go func() {
		time.Sleep(3 * time.Second)
		fyne.Do(func() {
			if a.infoLabel.Text == s {
				a.infoLabel.SetText("")
			}
		})
	}()
}

// buildMain mirrors the main form: tabs, menu and status bar.
func (a *App) buildMain() {
	a.status = widget.NewLabel("")
	a.infoLabel = widget.NewLabel("")
	a.tabs = container.NewAppTabs(
		container.NewTabItemWithIcon("Wallet", theme.AccountIcon(), a.walletTab()),
		container.NewTabItemWithIcon("Console", theme.ComputerIcon(), a.consoleTab()),
		container.NewTabItemWithIcon("Monitor", theme.InfoIcon(), a.monitorTab()),
		container.NewTabItemWithIcon("Masternodes", theme.StorageIcon(), a.mnTab()),
		container.NewTabItemWithIcon("GVTs", theme.ListIcon(), a.gvtTab()),
		container.NewTabItemWithIcon("Options", theme.SettingsIcon(), a.optionsTab()),
	)
	if t := codec.StrToIntDef(os.Getenv("NOSO_GUI_TAB"), 0); t > 0 && int(t) < len(a.tabs.Items) {
		a.tabs.SelectIndex(int(t))
	}
	a.win.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu("File",
		fyne.NewMenuItem("Import wallet...", a.importWallet),
		fyne.NewMenuItem("Export wallet...", a.exportWallet),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { a.shutdown() }))))
	a.win.SetContent(container.NewBorder(nil, container.NewHBox(a.status, a.infoLabel), nil, nil, a.tabs))
	a.win.SetCloseIntercept(func() { a.shutdown() })
	if !a.headless { // tests call refresh themselves: the test driver runs fyne.Do inline
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-a.done:
					return
				case <-t.C:
					fyne.Do(a.refresh)
				}
			}
		}()
	}
	a.refresh()
}

// shutdown mirrors CloseeAppSafely. Every way out of the program (window
// close, File > Quit, the console quit command) goes through it, once.
func (a *App) shutdown() {
	a.closing.Do(func() {
		close(a.done)
		if a.n != nil {
			_ = a.n.SaveOptions()
			a.r.Stop()
			a.e.Stop()
			_ = os.WriteFile(a.n.Lay.ClosedMarker, nil, 0o644)
			if a.ctl != nil {
				_ = a.ctl.Close()
			}
			if a.lock != nil {
				_ = a.lock.Close()
			}
		}
		a.fa.Quit()
	})
}

// refresh mirrors ActualizarGUI/UpdateStatusBar (1 s).
func (a *App) refresh() {
	n, e := a.n, a.e
	conn := map[int]string{0: "disconnected", 1: "connecting", 2: "connected", 3: "updated"}[n.ConStatus()]
	srv, rp := "off", "off"
	if e.ServerActive() {
		srv = "on"
	}
	if a.r.Active() {
		rp = "on"
	}
	a.status.SetText(fmt.Sprintf("%s | peers %d (synced %d) | block %d | pending %d | server %s | rpc %s | %s",
		conn, e.TotalConnections(), e.SyncedConnections(), n.MyLastBlock(), n.PendingCount(), srv, rp,
		time.Unix(n.UTCTime(), 0).UTC().Format("2006-01-02 15:04:05")))
	if n.Options().NoGUI {
		// WO_StopGUI: only the status bar is kept current; the tables, the
		// balance and the logs are not rebuilt every second.
		return
	}
	a.balance.SetText(network.Int2Curr(e.WalletBalance()) + " NOSO")
	// wallet grid
	a.addrRows = a.addrRows[:0]
	ws := n.Wallet.All()
	hide := n.Options().HideEmpty
	for _, w := range ws {
		bal := n.Summary.BalanceIndexed(w.Hash)
		if hide && bal == 0 {
			continue
		}
		mn := ""
		if strings.Contains(n.MNFile.Text(), w.Hash) {
			mn = " [MN]"
		}
		a.addrRows = append(a.addrRows, []string{w.Hash + mn, network.Int2Curr(bal)})
	}
	a.addrList.Refresh()
	a.dataRows = a.dataGridRows()
	a.dataGrid.Refresh()
	a.slotRows = a.slotRowsNow()
	a.slotsGrid.Refresh()
	a.consRows = a.consRowsNow()
	a.consGrid.Refresh()
	a.mnRows = a.mnRowsNow()
	a.mnGrid.Refresh()
	a.gvtRows = a.gvtRowsNow()
	a.gvtGrid.Refresh()
	a.mu.Lock()
	setIfChanged(a.console, strings.Join(a.consoleBuf, "\n"))
	setIfChanged(a.eventsLog, strings.Join(a.eventsBuf, "\n"))
	setIfChanged(a.excepLog, strings.Join(a.exceptsBuf, "\n"))
	a.mu.Unlock()
}

func setIfChanged(e *widget.Entry, s string) {
	if e != nil && e.Text != s {
		e.SetText(s)
		e.CursorRow = len(strings.Split(s, "\n"))
	}
}

func (a *App) dataGridRows() [][]string {
	n, e := a.n, a.e
	srv := "OFF"
	if e.ServerActive() {
		srv = "ON"
	}
	next := consensus.NextBlockTimeStamp(n.UTCTime()) - n.UTCTime()
	return [][]string{
		{"Merkle", codec.Copy(e.GetConsensus(0), 1, 5), "PSOs", codec.Copy(n.PSOs.FileHash(), 1, 5)},
		{"Server", srv, "Next", fmt.Sprintf("%ds", next)},
		{"Connections", fmt.Sprint(e.TotalConnections()), "Clients", fmt.Sprint(e.IncomingConnections())},
		{"Headers", codec.Copy(n.Headers.Hash(), 1, 5), "OrdIndex", fmt.Sprint(n.DB.Records())},
		{"Summary", codec.Copy(n.Summary.Hash(), 1, 5), "NosoCFG", codec.Copy(n.CFG.Hash(), 1, 5)},
		{"Last block", codec.Copy(n.MyLastBlockHash(), 1, 5), "GVTs", codec.Copy(n.GVTs.Hash(), 1, 5)},
		{"Blocks", fmt.Sprint(n.MyLastBlock()), "Masternodes", codec.Copy(n.MNFile.Hash(), 1, 5)},
		{"Pending", fmt.Sprint(n.PendingCount()), "MNsCount", fmt.Sprint(n.MNsListLen())},
	}
}

func (a *App) slotRowsNow() [][]string {
	rows := [][]string{{"Slot", "Type", "IP", "Block", "Pending", "Status", "Version", "Peers", "MN"}}
	for i := 1; i <= network.MaxConnections; i++ {
		p := a.e.Peer(i)
		if p.Tipo == "" {
			continue
		}
		rows = append(rows, []string{fmt.Sprint(i), p.Tipo, p.IP, p.LastBlock, fmt.Sprint(p.Pending),
			fmt.Sprint(p.ConexStatus), p.Version, fmt.Sprint(p.Connections), fmt.Sprint(p.MNsCount)})
	}
	return rows
}

func (a *App) consRowsNow() [][]string {
	s := a.e.ConsStats()
	rows := [][]string{{"#", "Item", "Value"}, {"", "Reached/Total", fmt.Sprintf("%d / %d (%d%%)", s.ReachedNodes, s.TotalNodes, s.Percentage)}}
	for i, v := range a.e.ConsensusItems() {
		name := ""
		if i < len(network.NConsensus) {
			name = network.NConsensus[i]
		}
		rows = append(rows, []string{fmt.Sprint(i), name, v})
	}
	return rows
}

func (a *App) mnRowsNow() [][]string {
	rows := [][]string{{"Node", "Funds", "Age"}}
	for _, m := range a.n.MNFile.Entries() {
		rows = append(rows, []string{m.IPAndPort, m.Address, fmt.Sprint(m.Age)})
	}
	for _, m := range a.n.MNsList() {
		rows = append(rows, []string{"reported " + m.IP, m.Fund, fmt.Sprint(m.Validations)})
	}
	return rows
}

func (a *App) gvtRowsNow() [][]string {
	rows := [][]string{{"#", "Address"}}
	for i, g := range a.n.GVTs.All() {
		rows = append(rows, []string{fmt.Sprintf("%02d", i), g.Owner})
	}
	return rows
}

// grid builds a read-only table over a row slice getter.
func grid(rows func() [][]string, widths ...float32) *widget.Table {
	t := widget.NewTable(
		func() (int, int) {
			r := rows()
			if len(r) == 0 {
				return 0, 1
			}
			return len(r), len(r[0])
		},
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			r := rows()
			if id.Row < len(r) && id.Col < len(r[id.Row]) {
				o.(*widget.Label).SetText(r[id.Row][id.Col])
			}
		})
	for i, w := range widths {
		t.SetColumnWidth(i, w)
	}
	return t
}

// ---- import / export (formexplore replaced by native file dialogs) ---------

func (a *App) importWallet() {
	dialog.ShowFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil || rc == nil {
			return
		}
		path := rc.URI().Path()
		rc.Close()
		a.runCommand("impwallet " + strings.ReplaceAll(path, " ", "*"))
	}, a.win)
}

// exportWallet asks for a directory and writes a new, plaintext wallet file
// there with the cli's expwallet. The file name is chosen here and the
// command refuses to overwrite: the previous version let the save dialog
// create the target and then deleted it, which could be the live wallet
// (finding 2a).
func (a *App) exportWallet() {
	dialog.ShowFolderOpen(func(dir fyne.ListableURI, err error) {
		if err != nil || dir == nil {
			return
		}
		p := exportPath(dir.Path(), time.Now().Format("20060102-150405"), storage.Exists)
		a.runCommand("expwallet " + strings.ReplaceAll(strings.TrimSuffix(p, ".pkw"), " ", "*"))
	}, a.win)
}

var _ = filepath.Join
