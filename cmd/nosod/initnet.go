package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// devnetFile marks a data directory of a test network whose chain clock runs
// faster than real time. It is written by `nosod init-network -clock-scale`.
const devnetFile = "devnet.txt"

// bindFile holds the address the P2P listener of a data directory binds to.
// `nosod init-network` writes it (the -host/-bind value, loopback by default);
// `nosod -bind` overrides it; without either the node listens on every
// interface, as a public node must.
const bindFile = network.BindFile

// readBind returns the bind address stored in a data directory, "" if none.
func readBind(dataDir string) string { return network.ReadBind(dataDir) }

// planPorts returns the peer and RPC port of every node. A rpcBase of 0 puts
// the RPC ports right after the peer ports (base..base+n-1, then base+n..); a
// negative one means no RPC. It refuses ports out of range and any port used
// twice, so no two nodes of one machine can ever fight over one.
func planPorts(nodes, base, rpcBase int) (peer, rpc []int, err error) {
	if rpcBase == 0 {
		rpcBase = base + nodes
	}
	used := map[int]string{}
	claim := func(port int, what string) error {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s port %d is out of range 1..65535", what, port)
		}
		if prev, dup := used[port]; dup {
			return fmt.Errorf("%s port %d is already used by %s; choose -base-port and -rpc-base-port ranges that do not overlap", what, port, prev)
		}
		used[port] = what
		return nil
	}
	for i := 0; i < nodes; i++ {
		p := base + i
		if err := claim(p, fmt.Sprintf("node%d peer", i+1)); err != nil {
			return nil, nil, err
		}
		peer = append(peer, p)
	}
	for i := 0; i < nodes && rpcBase > 0; i++ {
		p := rpcBase + i
		if err := claim(p, fmt.Sprintf("node%d RPC", i+1)); err != nil {
			return nil, nil, err
		}
		rpc = append(rpc, p)
	}
	return peer, rpc, nil
}

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
  nosod init-network -dir DIR [-nodes 4] [-proposers 3] [-host 127.0.0.1] [-bind ADDR]
                     [-base-port 18080] [-rpc-base-port N] [-clock-scale N]
                     [-local-masternodes auto|yes|no]
      Creates a new network on this machine: DIR/node1 ... DIR/nodeN, each with
      its own wallet, the same proposers file (the first -proposers nodes),
      the same seed list (all nodes) and ports base-port+i / rpc-base-port+i.
      -host is the address the nodes tell each other (seeds, masternode IP);
      the P2P listener binds -bind, which defaults to -host, so the default
      network never leaves loopback. The RPC server always binds loopback.
      The default RPC ports follow the peer ports (base-port+nodes+i); ports
      that overlap or are out of range are refused.
      Every node gets the same network.txt: a random chain id (orders signed on
      another network are refused) and the local_masternodes rule (yes when
      -host is loopback, so masternodes may use 127.0.0.1; no otherwise). The
      file is part of what blocks commit to; do not edit it.
      Works for any number of nodes from 1. Prints the public keys, never a
      private key. -clock-scale N runs the chain clock N times faster than real
      time (test networks only, see docs/running-a-node.md).
  nosod init-network -data DATADIR -proposer-keys FILE [-network-file FILE] [-seed host:port]... [-propose] [-bind ADDR]
      Prepares one data directory to join (or serve) a network made elsewhere:
      imports the public keys of the proposers (one per line), the seeds and,
      when the network has one, its network.txt (copy it from any node of the
      network; without it the node would be on another chain).

The wallet passphrase comes from NOSO_WALLET_PASSPHRASE or -wallet-pass-file
and is shared by the wallets this command creates.`

// outf and outln write a message to the terminal. A failed write to stdout or
// stderr has nowhere to be reported, so the error is dropped here, once.
func outf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func outln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }

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
	host := fs.String("host", "127.0.0.1", "address the nodes tell each other (seeds, masternode IP)")
	bind := fs.String("bind", "", "address the P2P listeners bind (default: the -host value)")
	basePort := fs.Int("base-port", 18080, "peer port of node1; node i uses base+i-1")
	rpcBase := fs.Int("rpc-base-port", 0, "RPC port of node1; node i uses base+i-1 (default: base-port+nodes; negative: no RPC)")
	scale := fs.Int64("clock-scale", 1, "chain clock speed-up (test networks only)")
	localMN := fs.String("local-masternodes", "auto", "masternodes may use loopback/private addresses: auto (yes when -host is loopback), yes or no")
	netFile := fs.String("network-file", "", "with -data: the network.txt of the network to join")
	passFile := fs.String("wallet-pass-file", "", "file holding the wallet passphrase")
	data := fs.String("data", "", "single data directory to configure")
	keysFile := fs.String("proposer-keys", "", "file with the public keys of the proposers")
	propose := fs.Bool("propose", false, "this node builds blocks (its wallet key must be in the proposers file)")
	var seeds seedList
	fs.Var(&seeds, "seed", "host:port of a node of the network (repeatable)")
	if err := fs.Parse(args); err != nil {
		outln(stderr, initUsage)
		return 2
	}
	pass, err := walletPassphrase(*passFile)
	if err != nil || len(pass) == 0 {
		outln(stderr, "init-network: a wallet passphrase is required (NOSO_WALLET_PASSPHRASE or -wallet-pass-file)")
		return 2
	}
	if *data != "" {
		return joinNetwork(*data, pass, *keysFile, *netFile, seeds, *propose, *bind, stdout, stderr)
	}
	if *dir == "" || *nodes < 1 || *props < 1 || *props > *nodes || *scale < 1 {
		outln(stderr, initUsage)
		return 2
	}
	peerPorts, rpcPorts, err := planPorts(*nodes, *basePort, *rpcBase)
	if err != nil {
		outln(stderr, "init-network:", err)
		return 2
	}
	bindAddr := *bind
	if bindAddr == "" {
		bindAddr = *host
	}
	// FIX(F-18): one random chain id per network, the same file on every node.
	local := isLoopbackHost(*host)
	switch *localMN {
	case "auto":
	case "yes":
		local = true
	case "no":
		local = false
	default:
		outln(stderr, "init-network: -local-masternodes is auto, yes or no")
		return 2
	}
	netCfg, err := node.NewNetworkConfig(local)
	if err != nil {
		outln(stderr, "init-network:", err)
		return 1
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
			outf(stderr, "init-network: %s already holds a wallet; refusing to overwrite a network\n", d)
			return 1
		}
		if err := cli.CheckNewPassphrase(d, pass); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		l, err := storage.LockDataDir(d)
		if err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		locks = append(locks, l)
		// the network file is written before the node first opens its data
		// (the node reads it then), so nothing ever runs on a default
		if err := node.WriteNetworkConfig(d, netCfg); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		n, err := node.NewWithConfig(d, node.Config{WalletPassphrase: pass})
		if err != nil {
			outf(stderr, "init-network: %s: %v\n", d, err)
			return 1
		}
		ns = append(ns, n)
	}
	var keys []string
	for i := 0; i < *props; i++ {
		keys = append(keys, ns[i].Wallet.At(0).PublicKey)
	}
	anchor := time.Now().Unix()
	// FIX(F-9): the key that signs masternode challenges answers any peer, so
	// a proposer node gets a second address for it; the proposer key never
	// does that.
	signAddr := make([]string, len(ns))
	for i, n := range ns {
		signAddr[i] = n.Wallet.At(0).Hash
		if i < *props {
			w, err := n.Wallet.NewAddress()
			if err != nil {
				outln(stderr, "init-network:", err)
				return 1
			}
			signAddr[i] = w.Hash
		}
	}
	for i, n := range ns {
		// FIX: the same list on every node, the node itself included. The
		// status hash the nodes vote on contains a hash of the configuration,
		// so lists that differ (each without its own node) never agree and no
		// consensus can form: getmainnetinfo fails and no masternode is listed.
		// A node never dials itself.
		var sl []string
		for j := range ns {
			sl = append(sl, fmt.Sprintf("%s;%d:", *host, peerPorts[j]))
		}
		writeSeeds(n, strings.Join(sl, ""))
		if err := n.SetProposers(keys); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		n.UpdateOptions(func(o *node.StorageOptions) {
			o.AutoServer = true
			o.BuildBlocks = i < *props
			o.MNIP = *host
			o.MNPort = strconv.Itoa(peerPorts[i])
			o.MNSign = signAddr[i]
			if len(rpcPorts) > 0 {
				o.RPCAuto = true
				o.RPCPort = rpcPorts[i]
			}
		})
		n.EnsureRPCTokens()
		if err := n.SaveOptions(); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		if err := os.WriteFile(filepath.Join(n.Lay.Root, bindFile), []byte(bindAddr+"\n"), 0o600); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		if *scale > 1 {
			m := fmt.Sprintf("anchor %d\nbase %d\nscale %d\n", anchor, anchor, *scale)
			if err := os.WriteFile(filepath.Join(n.Lay.Root, devnetFile), []byte(m), 0o600); err != nil {
				outln(stderr, "init-network:", err)
				return 1
			}
		}
	}
	outf(stdout, "Network of %d nodes (%d proposers) created in %s\n", *nodes, *props, *dir)
	outln(stdout, "Proposer public keys (in rank order, also in every proposers.txt):")
	for i, k := range keys {
		outf(stdout, "  %d  %s  (%s)\n", i+1, k, ns[i].Wallet.At(0).Hash)
	}
	if *scale > 1 {
		outf(stdout, "\nTEST NETWORK: the chain clock of these nodes runs %dx faster than real time.\n", *scale)
		outln(stdout, "Never connect them to a network you do not own.")
	}
	outln(stdout, "\nStart every node in its own shell (the same passphrase for all):")
	for i := 1; i <= *nodes; i++ {
		outf(stdout, "  nosod -data %s -no-ntp\n", filepath.Join(*dir, fmt.Sprintf("node%d", i)))
	}
	return 0
}

// isLoopbackHost reports whether host names this machine only.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// writeSeeds replaces the seed field of the node's nosocfg.psk.
func writeSeeds(n *node.Node, seeds string) {
	if seeds == "" {
		seeds = "null:"
	}
	_ = n.CFG.SetData(seeds, 1)
}

// joinNetwork configures one data directory for an existing network.
func joinNetwork(data string, pass []byte, keysFile, netFile string, seeds []string, propose bool, bind string, stdout, stderr *os.File) int {
	if keysFile == "" {
		outln(stderr, "init-network: -proposer-keys is required with -data")
		return 2
	}
	raw, err := os.ReadFile(keysFile)
	if err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	var keys []string
	for _, l := range strings.Split(string(raw), "\n") {
		// `nosocli pubkey` prints "ADDRESS KEY": the key is the last field, so
		// its output can be used as it is, one line per proposer
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			keys = append(keys, f[len(f)-1])
		}
	}
	if err := cli.CheckNewPassphrase(data, pass); err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	lock, err := storage.LockDataDir(data)
	if err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	defer func() {
		if err := lock.Close(); err != nil {
			outln(stderr, "init-network: releasing the data directory lock:", err)
		}
	}()
	if netFile != "" {
		rawNet, err := os.ReadFile(netFile)
		if err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		cfg, err := node.ParseNetworkConfig(string(rawNet))
		if err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
		if err := node.WriteNetworkConfig(data, cfg); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
	}
	n, err := node.NewWithConfig(data, node.Config{WalletPassphrase: pass})
	if err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	if err := n.SetProposers(keys); err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	var sl string
	for _, s := range seeds {
		h, p, ok := strings.Cut(s, ":")
		if !ok || h == "" || codec.StrToIntDef(p, -1) < 1 {
			outf(stderr, "init-network: bad seed %q, want host:port\n", s)
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
		outln(stderr, "init-network: -propose, but the first wallet key is not in the proposers file")
		return 1
	}
	n.UpdateOptions(func(o *node.StorageOptions) { o.AutoServer = true; o.BuildBlocks = propose })
	n.EnsureRPCTokens()
	if err := n.SaveOptions(); err != nil {
		outln(stderr, "init-network:", err)
		return 1
	}
	if bind != "" {
		if err := os.WriteFile(filepath.Join(data, bindFile), []byte(bind+"\n"), 0o600); err != nil {
			outln(stderr, "init-network:", err)
			return 1
		}
	}
	outf(stdout, "%s: %d proposers, %d seeds, builds blocks: %v\nthis node's public key: %s\n",
		data, len(keys), len(seeds), propose, mine)
	return 0
}
