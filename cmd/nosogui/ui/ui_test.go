//go:build gui

package ui

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/node"
)

// shotDir is where the screenshots go: NOSO_GUI_SHOTS, or nowhere.
func shotDir() string { return os.Getenv("NOSO_GUI_SHOTS") }

func newTestApp(t *testing.T) *App {
	t.Helper()
	a := newApp(test.NewApp(), filepath.Join(t.TempDir(), "NOSODATA"))
	a.headless = true
	if err := a.startNode([]byte("test passphrase"), false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	// three funded addresses; the default wallet has one
	for len(a.n.Wallet.All()) < 3 {
		if _, err := a.e.NewAddress(); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range a.n.Wallet.All() {
		a.n.Summary.CreditTo(w.Hash, 1_000_000_000, 1)
	}
	if err := a.n.Summary.UpdateChanges(); err != nil {
		t.Fatal(err)
	}
	a.buildMain()
	t.Cleanup(a.shutdown)
	return a
}

// shot writes the window as a PNG when NOSO_GUI_SHOTS is set. It always
// renders, so a widget that cannot draw fails the test.
func shot(t *testing.T, a *App, name string) {
	t.Helper()
	a.refresh()
	img := a.win.Canvas().Capture()
	if img == nil || img.Bounds().Dx() < 100 || img.Bounds().Dy() < 100 {
		t.Fatalf("%s: nothing rendered", name)
	}
	if dir := shotDir(); dir != "" {
		f, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := png.Encode(f, img); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func (a *App) consoleText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.consoleBuf, "\n")
}

// Every tab and sub tab renders.
func TestEveryTabRenders(t *testing.T) {
	a := newTestApp(t)
	names := []string{"wallet", "console", "monitor", "masternodes", "gvts", "options"}
	for i, n := range names {
		a.tabs.SelectIndex(i)
		shot(t, a, "tab-"+n)
	}
	a.tabs.SelectIndex(2)
	for i, n := range []string{"data", "connections", "consensus", "events", "exceptions", "processes"} {
		a.monTabs.SelectIndex(i)
		shot(t, a, "monitor-"+n)
	}
	a.tabs.SelectIndex(5)
	for i, n := range []string{"wallet", "node", "rpc", "about"} {
		a.optTabs.SelectIndex(i)
		shot(t, a, "options-"+n)
	}
}

// The critical flow of finding 13: select the third address, send, and the
// order must come from that address.
func TestSendFromSelectedAddress(t *testing.T) {
	a := newTestApp(t)
	a.tabs.SelectIndex(0)
	a.refresh()
	third := a.n.Wallet.At(2).Hash
	if got := addressFromRow(a.addrRows, 2); got != third {
		t.Fatalf("row 2 shows %q, wallet[2] is %q", got, third)
	}
	a.addrList.Select(widget.TableCellID{Row: 2, Col: 0})
	if a.selAddr != third {
		t.Fatalf("selection %q", a.selAddr)
	}
	shot(t, a, "wallet-selected")
	dest := crypto.GetAddressFromPublicKey(crypto.GenerateKeyPair().PublicKey, 0)
	test.Type(a.sendDest, dest)
	a.sendAmount.SetText("5.00000000")
	test.Tap(a.sendBtn)
	if !a.confBtn.Visible() {
		t.Fatal("send did not ask for confirmation")
	}
	shot(t, a, "wallet-confirm")
	a.e.TraceOrder = func(l string) { a.appendLog("console", "Send to Node "+l) }
	test.Tap(a.confBtn)
	waitFor(t, "order line in the console", func() bool { return strings.Contains(a.consoleText(), "Send to Node") })
	var order string
	for _, l := range strings.Split(a.consoleText(), "\n") {
		if strings.HasPrefix(l, "Send to Node") {
			order = l
		}
	}
	if !strings.Contains(order, third) {
		t.Fatalf("order not sent from the selected address %s:\n%s", third, order)
	}
	for _, w := range a.n.Wallet.All()[:2] {
		if strings.Contains(order, w.Hash) {
			t.Fatalf("order also uses %s", w.Hash)
		}
	}
}

// Console: a typed command runs and shows its output; restart is refused
// instead of quitting.
func TestConsoleCommands(t *testing.T) {
	a := newTestApp(t)
	a.tabs.SelectIndex(1)
	run := func(cmd string) {
		test.Type(a.consoleIn, cmd)
		a.consoleIn.TypedKey(&fyne.KeyEvent{Name: fyne.KeyReturn})
	}
	run("balance")
	waitFor(t, "balance output", func() bool { return strings.Contains(a.consoleText(), "NOSO") })
	run("restart")
	waitFor(t, "restart answer", func() bool { return strings.Contains(a.consoleText(), "cannot restart itself") })
	shot(t, a, "console-after-commands")
	select {
	case <-a.done:
		t.Fatal("restart closed the program")
	default:
	}
}

// Options: a checkbox changes the stored option and the address grid.
func TestHideEmptyOption(t *testing.T) {
	a := newTestApp(t)
	a.refresh()
	all := len(a.addrRows)
	a.n.Summary.Pay(a.n.Wallet.At(1).Hash, 1_000_000_000, 2) // make one address empty
	_ = a.n.Summary.UpdateChanges()
	a.tabs.SelectIndex(5)
	a.optTabs.SelectIndex(0)
	test.Tap(a.hideCheck)
	if !a.n.Options().HideEmpty {
		t.Fatal("option not stored")
	}
	a.refresh()
	if len(a.addrRows) != all-1 {
		t.Fatalf("rows %d, want %d", len(a.addrRows), all-1)
	}
}

// Every way out goes through shutdown once.
func TestShutdownOnce(t *testing.T) {
	a := newTestApp(t)
	a.shutdown()
	a.shutdown()
	select {
	case <-a.done:
	default:
		t.Fatal("not shut down")
	}
	if _, err := os.Stat(a.n.Lay.ClosedMarker); err != nil {
		t.Fatalf("closed marker missing: %v", err)
	}
}

// The "No GUI refresh" option (NoGUI) keeps the tables and the balance still;
// only the status bar goes on. Unchecking it brings them up to date again.
func TestNoGUIOptionStopsTheRefresh(t *testing.T) {
	a := newTestApp(t)
	a.refresh()
	before := a.balance.Text
	a.n.UpdateOptions(func(o *node.StorageOptions) { o.NoGUI = true })
	a.n.Summary.CreditTo(a.n.Wallet.At(0).Hash, 5_000_000_000, 2)
	if err := a.n.Summary.UpdateChanges(); err != nil {
		t.Fatal(err)
	}
	a.refresh()
	if a.balance.Text != before {
		t.Fatalf("NoGUI is set, but the balance was refreshed: %q -> %q", before, a.balance.Text)
	}
	a.n.UpdateOptions(func(o *node.StorageOptions) { o.NoGUI = false })
	a.refresh()
	if a.balance.Text == before {
		t.Fatal("the refresh did not resume")
	}
}

// A network made by init-network stays where its bind.txt says, also when the
// desktop app runs the node.
func TestStartNodeHonoursBindFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "NOSODATA")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bind.txt"), []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newApp(test.NewApp(), dir)
	a.headless = true
	if err := a.startNode([]byte("test passphrase"), false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.shutdown)
	if a.e.BindAddr != "127.0.0.1" {
		t.Fatalf("BindAddr = %q", a.e.BindAddr)
	}
}
