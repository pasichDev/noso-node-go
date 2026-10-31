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
	"sync"
	"syscall"
	"time"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/rpc"
)

func main() {
	data := flag.String("data", "NOSODATA", "data directory (same layout as the original NOSODATA folder)")
	noSeeds := flag.Bool("no-seed-download", false, "do not download the default seed list on first start")
	noP2P := flag.Bool("no-p2p", false, "open the data directory and the RPC server but do not connect to peers")
	noNTP := flag.Bool("no-ntp", false, "do not query NTP servers at start")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *version {
		fmt.Println(node.MainnetVersion + node.NodeRelease + " (nosod, independent Go implementation)")
		return
	}

	var fetch func() string
	if !*noSeeds {
		fetch = cli.FetchDefaultSeeds
	}
	n, err := node.New(*data, fetch)
	if err != nil {
		log.Fatalf("cannot open data directory: %v", err)
	}
	logf := func(ch, msg string) { log.Printf("[%s] %s", ch, msg) }
	n.Log = logf
	e := network.NewEngine(n)
	e.Log = logf
	r := rpc.New(e)
	r.Log = logf
	d := cli.New(n, e, r)

	stop := make(chan bool, 1)
	d.Quit = func(restart bool) { stop <- restart }
	r.Restart = func() { stop <- true }
	e.CommandHook = func(line string) { d.RunTo(line, func(s string) { logf("console", s) }) }

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
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			if !*noNTP {
				e.UpdateTimeOffset(n.CFG.Param(2))
			}
		}
	}()

	logf("console", "Noso "+node.MainnetVersion+node.NodeRelease+" ready, last block "+codec.IntToStr(n.MyLastBlock())+
		", data in "+absPath(*data))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-stop:
	}
	logf("console", "Closing wallet")
	_ = n.SaveOptions()
	r.Stop()
	if ln != nil {
		_ = ln.Close()
		_ = os.Remove(control.SocketPath(*data))
	}
	e.Stop()
	_ = os.WriteFile(n.Lay.ClosedMarker, nil, 0o644)
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
