package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// devnetFile marks a data directory of a test network whose chain clock runs
// faster than real time. It is written by `nosod init-network -clock-scale`.
const devnetFile = "devnet.txt"

// devClock is the chain clock of a test network: base + (wall - anchor) *
// scale. It is a pure function of the wall clock, so every node of the
// network, started at any time and restarted at will, shows the same time.
type devClock struct{ anchor, base, scale int64 }

func readDevClock(dataDir string) (devClock, bool) {
	raw, err := os.ReadFile(filepath.Join(dataDir, devnetFile))
	if err != nil {
		return devClock{}, false
	}
	var c devClock
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "anchor":
			c.anchor = v
		case "base":
			c.base = v
		case "scale":
			c.scale = v
		}
	}
	return c, c.anchor > 0 && c.scale > 1
}

func (c devClock) now() int64 {
	return c.base + int64(float64(time.Now().UnixNano()-c.anchor*1e9)/1e9*float64(c.scale))
}

const initUsage = `usage:
  nosod init-network -dir DIR [-nodes 4] [-proposers 3] [-host 127.0.0.1] [-base-port 18080]
                     [-rpc-base-port 18078] [-clock-scale N]
      Creates a new network on this machine: DIR/node1 ... DIR/nodeN, each with
      its own wallet, the same proposers file (the first -proposers nodes),
      a seed list of the other nodes, and ports base-port+i / rpc-base-port+i.
      Works for any number of nodes from 1. Prints the public keys, never a
      private key. -clock-scale N runs the chain clock N times faster than real
      time (test networks only, see docs/running-a-node.md).
  nosod init-network -data DATADIR -proposer-keys FILE [-seed host:port]... [-propose]
      Prepares one data directory to join (or serve) a network made elsewhere:
      imports the public keys of the proposers (one per line) and the seeds.

The wallet passphrase comes from NOSO_WALLET_PASSPHRASE or -wallet-pass-file
and is shared by the wallets this command creates.`

type seedList []string

func (s *seedList) String() string     { return strings.Join(*s, ",") }
func (s *seedList) Set(v string) error { *s = append(*s, v); return nil }

// initNetwork implements `nosod init-network`.
func initNetwork(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("init-network", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory that receives node1..nodeN")
	nodes := fs.Int("nodes", 4, "number of nodes")
	props := fs.Int("proposers", 3, "how many of the nodes propose blocks")
	host := fs.String("host", "127.0.0.1", "address the nodes listen on and tell each other")
	basePort := fs.Int("base-port", 18080, "peer port of node1; node i uses base+i-1")
	rpcBase := fs.Int("rpc-base-port", 18078, "RPC port of node1; node i uses base+i-1 (negative: no RPC)")
	scale := fs.Int64("clock-scale", 1, "chain clock speed-up (test networks only)")
	passFile := fs.String("wallet-pass-file", "", "file holding the wallet passphrase")
	data := fs.String("data", "", "single data directory to configure")
	keysFile := fs.String("proposer-keys", "", "file with the public keys of the proposers")
	propose := fs.Bool("propose", false, "this node builds blocks (its wallet key must be in the proposers file)")
	var seeds seedList
	fs.Var(&seeds, "seed", "host:port of a node of the network (repeatable)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, initUsage)
		return 2
	}
	pass, err := walletPassphrase(*passFile)
	if err != nil || len(pass) == 0 {
		fmt.Fprintln(stderr, "init-network: a wallet passphrase is required (NOSO_WALLET_PASSPHRASE or -wallet-pass-file)")
		return 2
	}
	if *data != "" {
		return joinNetwork(*data, pass, *keysFile, seeds, *propose, stdout, stderr)
	}
	if *dir == "" || *nodes < 1 || *props < 1 || *props > *nodes || *scale < 1 {
		fmt.Fprintln(stderr, initUsage)
		return 2
	}
	// Open all wallets first: the proposers file needs every key.
	var ns []*node.Node
	var locks []*storage.DirLock
	defer func() {
		for _, l := range locks {
			_ = l.Close()
		}
	}()
	for i := 1; i <= *nodes; i++ {
		d := filepath.Join(*dir, fmt.Sprintf("node%d", i))
		if _, err := os.Stat(filepath.Join(d, "wallet.enc")); err == nil {
			fmt.Fprintf(stderr, "init-network: %s already holds a wallet; refusing to overwrite a network\n", d)
			return 1
		}
		if err := cli.CheckNewPassphrase(d, pass); err != nil {
			fmt.Fprintln(stderr, "init-network:", err)
			return 1
		}
		l, err := storage.LockDataDir(d)
		if err != nil {
			fmt.Fprintln(stderr, "init-network:", err)
			return 1
		}
		locks = append(locks, l)
		// the seed list is written before the node first opens its data, so
		// nothing ever dials a default
		n, err := node.NewWithConfig(d, node.Config{WalletPassphrase: pass})
		if err != nil {
			fmt.Fprintf(stderr, "init-network: %s: %v\n", d, err)
			return 1
		}
		ns = append(ns, n)
	}
	var keys []string
	for i := 0; i < *props; i++ {
		keys = append(keys, ns[i].Wallet.At(0).PublicKey)
	}
	anchor := time.Now().Unix()
	for i, n := range ns {
		var sl []string
		for j := range ns {
			if j != i {
				sl = append(sl, fmt.Sprintf("%s;%d:", *host, *basePort+j))
			}
		}
		writeSeeds(n, strings.Join(sl, ""))
		if err := n.SetProposers(keys); err != nil {
			fmt.Fprintln(stderr, "init-network:", err)
			return 1
		}
		n.UpdateOptions(func(o *node.StorageOptions) {
			o.AutoServer = true
			o.BuildBlocks = i < *props
			o.MNIP = *host
			o.MNPort = strconv.Itoa(*basePort + i)
			o.MNSign = n.Wallet.At(0).Hash
			if *rpcBase >= 0 {
				o.RPCAuto = true
				o.RPCPort = *rpcBase + i
			}
		})
		n.EnsureRPCTokens()
		if err := n.SaveOptions(); err != nil {
			fmt.Fprintln(stderr, "init-network:", err)
			return 1
		}
		if *scale > 1 {
			m := fmt.Sprintf("anchor %d\nbase %d\nscale %d\n", anchor, anchor, *scale)
			if err := os.WriteFile(filepath.Join(n.Lay.Root, devnetFile), []byte(m), 0o600); err != nil {
				fmt.Fprintln(stderr, "init-network:", err)
				return 1
			}
		}
	}
	fmt.Fprintf(stdout, "Network of %d nodes (%d proposers) created in %s\n", *nodes, *props, *dir)
	fmt.Fprintln(stdout, "Proposer public keys (in rank order, also in every proposers.txt):")
	for i, k := range keys {
		fmt.Fprintf(stdout, "  %d  %s  (%s)\n", i+1, k, ns[i].Wallet.At(0).Hash)
	}
	if *scale > 1 {
		fmt.Fprintf(stdout, "\nTEST NETWORK: the chain clock of these nodes runs %dx faster than real time.\n", *scale)
		fmt.Fprintln(stdout, "Never connect them to a network you do not own.")
	}
	fmt.Fprintln(stdout, "\nStart every node in its own shell (the same passphrase for all):")
	for i := 1; i <= *nodes; i++ {
		fmt.Fprintf(stdout, "  nosod -data %s -no-ntp\n", filepath.Join(*dir, fmt.Sprintf("node%d", i)))
	}
	return 0
}

// writeSeeds replaces the seed field of the node's nosocfg.psk.
func writeSeeds(n *node.Node, seeds string) {
	if seeds == "" {
		seeds = "null:"
	}
	_ = n.CFG.SetData(seeds, 1)
}

// joinNetwork configures one data directory for an existing network.
func joinNetwork(data string, pass []byte, keysFile string, seeds []string, propose bool, stdout, stderr *os.File) int {
	if keysFile == "" {
		fmt.Fprintln(stderr, "init-network: -proposer-keys is required with -data")
		return 2
	}
	raw, err := os.ReadFile(keysFile)
	if err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	var keys []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	if err := cli.CheckNewPassphrase(data, pass); err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	lock, err := storage.LockDataDir(data)
	if err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	defer lock.Close()
	n, err := node.NewWithConfig(data, node.Config{WalletPassphrase: pass})
	if err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	if err := n.SetProposers(keys); err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	var sl string
	for _, s := range seeds {
		h, p, ok := strings.Cut(s, ":")
		if !ok || h == "" || codec.StrToIntDef(p, -1) < 1 {
			fmt.Fprintf(stderr, "init-network: bad seed %q, want host:port\n", s)
			return 2
		}
		sl += h + ";" + p + ":"
	}
	writeSeeds(n, sl)
	mine := n.Wallet.At(0).PublicKey
	listed := false
	for _, k := range keys {
		listed = listed || k == mine
	}
	if propose && !listed {
		fmt.Fprintln(stderr, "init-network: -propose, but the first wallet key is not in the proposers file")
		return 1
	}
	n.UpdateOptions(func(o *node.StorageOptions) { o.AutoServer = true; o.BuildBlocks = propose })
	n.EnsureRPCTokens()
	if err := n.SaveOptions(); err != nil {
		fmt.Fprintln(stderr, "init-network:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: %d proposers, %d seeds, builds blocks: %v\nthis node's public key: %s\n",
		data, len(keys), len(seeds), propose, mine)
	return 0
}
