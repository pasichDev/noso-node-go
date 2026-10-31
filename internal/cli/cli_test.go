package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pasichDev/noso-node-go/internal/node"
)

func newDispatcher(t *testing.T) *Dispatcher {
	n, err := node.New(filepath.Join(t.TempDir(), "NOSODATA"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(n, nil, nil)
}

func TestCommands(t *testing.T) {
	d := newDispatcher(t)
	run := func(l string) string { return strings.Join(d.Run(l), "\n") }
	if run("ver") != "0.4.4Ab9" {
		t.Fatal(run("ver"))
	}
	if !strings.Contains(run("halving"), "From block       1 until  209999 : 50.00000000") ||
		!strings.Contains(run("halving"), "Final supply: 21000000.00000000") && !strings.Contains(run("halving"), "Final supply") {
		t.Fatal(run("halving"))
	}
	// Hand-derived: sha256("abc"), md5("abc") (nosocrypto.pas:177,189).
	if run("sha256 abc") != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" ||
		run("md5 abc") != "900150983CD24FB0D6963F7D28E17F72" {
		t.Fatal("hash commands")
	}
	if got := run("addfrompub BACo0LC7mWDn53orLANA2zKVSC1HfSe/jc/Ih7+cBQ1oh53Bu2Zo655WFmWnoKHEeaNflb1CR9WcfXuhmkKaY8Y="); got != "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df" {
		t.Fatal(got)
	}
	if !strings.Contains(run("supply"), "Current supply: 10303.90730000") {
		t.Fatal(run("supply"))
	}
	if !strings.HasPrefix(run("unknowncmd"), "Unknown command: unknowncmd") {
		t.Fatal(run("unknowncmd"))
	}
	if !strings.Contains(run("sendto N1 10"), "needs a running node") {
		t.Fatal(run("sendto N1 10"))
	}
	if !strings.Contains(run("gmts 100000000000"), "Match") {
		t.Fatal(run("gmts 100000000000"))
	}
	n0 := len(d.N.Wallet.All())
	run("newaddress")
	if len(d.N.Wallet.All()) != n0+1 {
		t.Fatal("newaddress")
	}
	cert := run("getcert " + d.N.Wallet.At(0).Hash + " exchange n0nce")
	parts := strings.Split(cert, "\n")
	if len(parts) != 2 {
		t.Fatalf("%q", cert)
	}
	if got := run("checkcert " + parts[1] + " exchange n0nce"); !strings.Contains(got, d.N.Wallet.At(0).Hash+" verified") {
		t.Fatal(got)
	}
	dir := t.TempDir()
	if out := run("expwallet " + filepath.Join(dir, "bak")); !strings.Contains(out, "Wallet saved as") {
		t.Fatal(out)
	}
	if run("expwallet "+filepath.Join(dir, "bak")) != "Error: Can not overwrite existing wallets" {
		t.Fatal("overwrite guard")
	}
	if _, err := os.Stat(filepath.Join(dir, "bak.pkw")); err != nil {
		t.Fatal(err)
	}
	d.Echo = true
	if out := d.Run("ver"); out[0] != ">> ver" {
		t.Fatal(out)
	}
	d.Echo = false
}

func TestEveryOriginalCommandHasAHandler(t *testing.T) {
	// The dispatch table of mpparser.pas:ParseCommandLine (lines 188-326).
	original := strings.Fields(`VER SERVERON SERVEROFF FORCESERVER NODES BOTS DISCONNECT OFFSET NEWADDRESS USEROPTIONS
	BALANCE CONNECTTO AUTOSERVERON AUTOSERVEROFF SHOWWALLET IMPWALLET EXPWALLET RESUMEN SETDEFAULT LBINFO TIMESTAMP
	UNDOBLOCK CUSTOMIZE SENDTO SENDGVT HALVING SETPORT SHA256 MD5 MD160 CLEAR TP BLOCK RESTART OSVERSION
	DIRECTIVE MYHASH STATUS GETCERT CHECKCERT RESTOREBLOCKCHAIN RESTORESUMARY SAVEADV ORDER
	ORDERSOURCES EXPORTADDRESS ADDRESS HISTORY TOTALFEES SUPPLY GMTS SHOWKEYS SHOWPENDING WEBWAL EXPKEYS ZIPSUMARY GETPOS GETMNS CLOSESTARTON CLOSESTARTOFF TT BASE58SUM PENDING HEADSIZE NEWFROMKEYS TESTHASH COMPARE
	GETREPOSEEDS FORCEREPOSEEDS GETDBLB ORDINFO GETMULTI DELBOTS SUMARY REBUILDSUM LISTGVT GVTINFO SYSTEM
	NOSOCFG FUNDS SUMINDEXSIZE MNSCHECKS TESTHEAD BLOCKPOS BLOCKMNS MYIP SETMODE ADDNODE DELNODE ADDPOOL DELPOOL
	RESTORECFG ADDNOSOPAY DELNOSOPAY ISALLSYNCED FREEZED CLEARCFG ADDFROMPUB CONSENSUS VALIDATE PEERS SETRPCPORT RPCON
	RPCOFF NEWPSO LISTPSOS CLEARPSOS SHOWPSOS CONSTATS POST`)
	for _, c := range original {
		if _, ok := handlers[c]; !ok {
			t.Errorf("missing handler for %s", c)
		}
	}
}

func FuzzDispatch(f *testing.F) {
	f.Add("sha256 abc")
	f.Add("getmulti 2,3 a,b,c")
	f.Fuzz(func(t *testing.T, line string) {
		d := newDispatcherFuzz()
		if strings.Contains(strings.ToUpper(line), "RESTOREBLOCKCHAIN") || strings.Contains(strings.ToUpper(line), "EXPWALLET") ||
			strings.Contains(strings.ToUpper(line), "EXPORTADDRESS") || strings.Contains(strings.ToUpper(line), "SYSTEM") ||
			strings.Contains(strings.ToUpper(line), "GETREPOSEEDS") || strings.Contains(strings.ToUpper(line), "FORCEREPOSEEDS") {
			return
		}
		d.Run(line)
	})
}

func newDispatcherFuzz() *Dispatcher {
	dir, _ := os.MkdirTemp("", "clifuzz")
	n, err := node.New(filepath.Join(dir, "NOSODATA"), nil)
	if err != nil {
		panic(err)
	}
	return New(n, nil, nil)
}
