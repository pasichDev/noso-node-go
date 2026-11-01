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
	"github.com/pasichDev/noso-node-go/internal/consensus"
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
	bind        string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "init-network" {
		os.Exit(initNetwork(os.Args[2:], os.Stdout, os.Stderr))
	}
	var o options
	flag.StringVar(&o.data, "data", "NOSODATA", "data directory (same layout as the original NOSODATA folder)")
	flag.StringVar(&o.seedURL, "seed-url", "", "https URL of a signed seed list (needs ReleaseKey in advopt.txt); nothing is downloaded without it")
	flag.StringVar(&o.passFile, "wallet-pass-file", "", "file holding the wallet passphrase (or set NOSO_WALLET_PASSPHRASE)")
	flag.BoolVar(&o.plainWallet, "insecure-plain-wallet", false, "keep private keys unencrypted in wallet.pkw (not recommended)")
	flag.BoolVar(&o.noP2P, "no-p2p", false, "open the data directory and the RPC server but do not connect to peers")
	flag.BoolVar(&o.noNTP, "no-ntp", false, "do not query NTP servers at start")
	flag.StringVar(&o.bind, "bind", "", "address the peer listener binds (e.g. 127.0.0.1 to stay on this machine); default: bind.txt of the data directory, else every interface")
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

// carriedLock is the data directory lock a restart hands to the next run.
var carriedLock *storage.DirLock

// run opens the node, serves until a signal or a stop request, closes
// everything and reports whether a restart was asked for.
func run(opt options, sig <-chan os.Signal) (restart bool) {
	data, seedURL, passFile := &opt.data, &opt.seedURL, &opt.passFile
	plainWallet, noP2P, noNTP := &opt.plainWallet, &opt.noP2P, &opt.noNTP
	pass, err := walletPassphrase(*passFile)
	if err != nil {
		log.Fatalf("wallet passphrase: %v", err)
	}
	if len(pass) == 0 && !*plainWallet {
		// before anything is written: a refusal must not leave a half-made data directory
		log.Fatalf("wallet passphrase: a passphrase is required (NOSO_WALLET_PASSPHRASE or -wallet-pass-file)")
	}
	if err := cli.CheckNewPassphrase(*data, pass); err != nil { // finding 20
		log.Fatalf("wallet passphrase: %v", err)
	}
	// FIX(C3): one process owns a data directory. The lock is kept for the whole
	// run (and released before a restart reopens the directory).
	// FIX(F-15): a restart keeps the lock it holds instead of releasing and
	// taking it again, so no other process (nosocli, the GUI) can open the
	// directory in the gap, and nothing here runs without it.
	lock := carriedLock
	carriedLock = nil
	if lock == nil {
		var err error
		if lock, err = storage.LockDataDir(*data); err != nil {
			log.Fatalf("cannot open data directory: %v", err)
		}
	}
	defer func() {
		if restart {
			carriedLock = lock
		} else {
			_ = lock.Close()
		}
	}()
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
	dev, isDev := readDevClock(*data)
	if isDev {
		n.SetClock(dev.now)
	}
	limiter := &logx.Limiter{Rate: 200}
	logf := func(ch, msg string) {
		if limiter.Allow() {
			log.Printf("[%s] %s", ch, logx.Sanitize(msg))
		}
	}
	n.Log = logf
	e := network.NewEngine(n)
	e.Log = logf
	e.BindAddr = opt.bind
	if e.BindAddr == "" {
		e.BindAddr = readBind(*data)
	}
	if isDev { // connection timers stay in real seconds, only the chain clock is fast
		e.Wall = func() int64 { return time.Now().Unix() }
		logf("console", fmt.Sprintf("TEST NETWORK: chain clock runs %dx faster than real time", dev.scale))
	}
	if w := n.Wallet.LegacyWarning(); w != "" {
		logf("console", w)
	}
	for _, w := range n.Wallet.Warnings() {
		logf("console", w)
	}
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
	d.CanRestart = true
	r.Restart = func() { ask(true) }

	if !*noNTP && !isDev {
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
	ln, err := control.Serve(control.SocketPath(*data), d.ControlRunner(pass))
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
				if !*noNTP && !isDev {
					e.UpdateTimeOffset(n.CFG.Param(2))
				}
			}
		}
	}()

	// PRestart N (advopt.txt): restart the node N block periods after it
	// started, in the quiet middle of a block period (KeepConnect, original).
	if o.PRestart > 0 {
		at := n.UTCTime() + o.PRestart*consensus.SecondsPerBlock
		logf("console", "PRestart set at "+time.Unix(at, 0).UTC().Format("2006-01-02 15:04:05"))
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-quit:
					return
				case <-t.C:
					if prestartDue(at, n.UTCTime(), n.BlockAge()) {
						ask(true)
						return
					}
				}
			}
		}()
	}

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
	}
	e.Stop()
	_ = os.WriteFile(n.Lay.ClosedMarker, nil, 0o644)
	return restart
}

// prestartDue reports whether the PRestart moment has come: the time is past
// the set point and the block period is neither about to end nor just begun.
func prestartDue(at, now, age int64) bool {
	return at > 0 && now > at && age > 120 && age < 450
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
