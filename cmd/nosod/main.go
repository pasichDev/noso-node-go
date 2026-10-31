// Command nosod is the Noso node daemon: peer-to-peer server and client,
// block builder, JSON-RPC server and local control socket.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/logx"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/rpc"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// options are the command line settings of one daemon run.
type options struct {
	data        string
	seedURL     string
	passFile    string
	plainWallet bool
	noP2P       bool
	noNTP       bool
}

func main() {
	var o options
	flag.StringVar(&o.data, "data", "NOSODATA", "data directory (same layout as the original NOSODATA folder)")
	flag.StringVar(&o.seedURL, "seed-url", "", "https URL of a signed seed list (needs ReleaseKey in advopt.txt); nothing is downloaded without it")
	flag.StringVar(&o.passFile, "wallet-pass-file", "", "file holding the wallet passphrase (or set NOSO_WALLET_PASSPHRASE)")
	flag.BoolVar(&o.plainWallet, "insecure-plain-wallet", false, "keep private keys unencrypted in wallet.pkw (not recommended)")
	flag.BoolVar(&o.noP2P, "no-p2p", false, "open the data directory and the RPC server but do not connect to peers")
	flag.BoolVar(&o.noNTP, "no-ntp", false, "do not query NTP servers at start")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *version {
		fmt.Println(node.MainnetVersion + node.NodeRelease + " (nosod, independent Go implementation)")
		return
	}
	// The signal handler lives across restarts. A restart (console
	// `restart`, RPC `restart`, `restoreblockchain`) closes everything and
	// opens the data directory again inside this process: nothing is
	// executed and no second binary is needed.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	for run(o, sig) {
		log.Printf("[console] restarting")
	}
}

// run opens the node, serves until a signal or a stop request, closes
// everything and reports whether a restart was asked for.
func run(opt options, sig <-chan os.Signal) (restart bool) {
	data, seedURL, passFile := &opt.data, &opt.seedURL, &opt.passFile
	plainWallet, noP2P, noNTP := &opt.plainWallet, &opt.noP2P, &opt.noNTP
	pass, err := walletPassphrase(*passFile)
	if err != nil {
		log.Fatalf("wallet passphrase: %v", err)
	}
	cfg := node.Config{WalletPassphrase: pass, InsecurePlainWallet: *plainWallet}
	if *seedURL != "" {
		cfg.FetchSeeds = func() string {
			// the release key lives in advopt.txt, read before the node opens
			var o storage.Options
			_ = o.Load(filepath.Join(*data, "advopt.txt"))
			return cli.FetchSeeds(*seedURL, o.ReleaseKey)
		}
	}
	n, err := node.NewWithConfig(*data, cfg)
	if err != nil {
		log.Fatalf("cannot open data directory: %v", err)
	}
	n.EnsureRPCTokens()
	limiter := &logx.Limiter{Rate: 200}
	logf := func(ch, msg string) {
		if limiter.Allow() {
			log.Printf("[%s] %s", ch, logx.Sanitize(msg))
		}
	}
	n.Log = logf
	e := network.NewEngine(n)
	e.Log = logf
	r := rpc.New(e)
	r.Log = logf
	d := cli.New(n, e, r)

	stop := make(chan bool, 4)
	ask := func(restart bool) {
		select {
		case stop <- restart:
		default:
		}
	}
	d.Quit = ask
	r.Restart = func() { ask(true) }
	e.CommandHook = func(line string) {
		if cli.Sensitive(line) { // FIX(H-10): never log key material
			d.RunTo(line, func(string) {})
			return
		}
		d.RunTo(line, func(s string) { logf("console", s) })
	}

	if !*noNTP {
		e.UpdateTimeOffset(n.CFG.Param(2))
	}
	if !*noP2P {
		e.Start()
	}
	o := n.Options()
	if o.RPCAuto {
		if err := r.Start(o.RPCPort); err != nil {
			logf("console", "Unable to start RPC port")
		} else {
			logf("console", "RPC server ENABLED")
		}
	}
	var wg sync.WaitGroup
	ln, err := control.Serve(control.SocketPath(*data), func(line string, out func(string)) { d.RunTo(line, out) })
	if err != nil {
		logf("console", "control socket unavailable: "+err.Error())
	}

	// Time offset refresh every period (heartbeat: age >= 570, NosoT_LastUpdate+599).
	quit := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				if !*noNTP {
					e.UpdateTimeOffset(n.CFG.Param(2))
				}
			}
		}
	}()

	logf("console", "Noso "+node.MainnetVersion+node.NodeRelease+" ready, last block "+codec.IntToStr(n.MyLastBlock())+
		", data in "+absPath(*data))
	select {
	case <-sig:
	case restart = <-stop:
	}
	logf("console", "Closing wallet")
	close(quit)
	wg.Wait()
	_ = n.SaveOptions()
	r.Stop()
	if ln != nil {
		_ = ln.Close()
		_ = os.Remove(control.SocketPath(*data))
	}
	e.Stop()
	_ = os.WriteFile(n.Lay.ClosedMarker, nil, 0o644)
	return restart
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// walletPassphrase reads the passphrase from a file or the environment.
func walletPassphrase(file string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		return []byte(strings.TrimRight(string(b), "\r\n")), err
	}
	return []byte(os.Getenv("NOSO_WALLET_PASSPHRASE")), nil
}
