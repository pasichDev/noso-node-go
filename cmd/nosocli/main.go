// Command nosocli runs the console commands of the Noso node from the
// shell. With a running nosod it talks to it over the control socket in the
// data directory. Without one it opens the data directory itself in offline
// mode (wallet and local chain commands), but only if it can take the
// exclusive lock of the directory: it never works beside a running node.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// readOnlyCommands never change the wallet: the wallet is opened read-only
// for them, so asking for the status cannot create or migrate anything.
var readOnlyCommands = map[string]bool{"STATUS": true, "VER": true, "BALANCE": true, "SHOWWALLET": true,
	"PUBKEY": true, "LBINFO": true, "TIMESTAMP": true, "NODES": true, "USEROPTIONS": true, "OFFSET": true}

func main() { os.Exit(run()) }

func run() int {
	data := flag.String("data", "NOSODATA", "data directory")
	list := flag.Bool("list", false, "list the supported commands")
	echo := flag.Bool("echo", false, "echo the command before running it")
	passFile := flag.String("wallet-pass-file", "", "file holding the wallet passphrase (or NOSO_WALLET_PASSPHRASE)")
	plain := flag.Bool("insecure-plain-wallet", false, "open a clear-text wallet.pkw")
	flag.Parse()
	if *list {
		for _, c := range cli.Commands() {
			fmt.Println(strings.ToLower(c))
		}
		return 0
	}
	var lock *storage.DirLock
	var d *cli.Dispatcher
	defer func() {
		if lock != nil {
			_ = lock.Close()
		}
	}()
	status := 0
	one := func(line string) {
		if err := control.Call(control.SocketPath(*data), line, os.Stdout); err == nil {
			return
		}
		if d == nil {
			var err error
			if d, lock, err = openOffline(*data, *passFile, *plain, *echo, flag.NArg() > 0 && readOnlyCommands[codec.ASCIIUpper(codec.Parameter(line, 0))]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				status = 1
				return
			}
		}
		d.RunTo(line, func(s string) { fmt.Println(s) })
	}
	if flag.NArg() > 0 {
		one(strings.Join(flag.Args(), " "))
		return status
	}
	sc := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "exit" || l == "quit" {
			return status
		}
		if l != "" {
			one(l)
		}
		fmt.Print("> ")
	}
	return status
}

// openOffline opens the data directory without a daemon. FIX(C3): it takes
// the directory lock first. If a daemon or the GUI holds it, the command is
// refused instead of becoming a second writer of the same wallet and chain
// files (which lost a private key).
func openOffline(data, passFile string, plain, echo, ro bool) (*cli.Dispatcher, *storage.DirLock, error) {
	lock, err := storage.LockDataDir(data)
	if err != nil {
		if errors.Is(err, storage.ErrDataDirLocked) {
			return nil, nil, fmt.Errorf("the data directory %s is in use by a running node that offers no control socket "+
				"(for example the GUI); close it first or use its console. Nothing was changed", data)
		}
		return nil, nil, fmt.Errorf("cannot open data directory: %w", err)
	}
	pass := []byte(os.Getenv("NOSO_WALLET_PASSPHRASE"))
	if passFile != "" {
		b, err := os.ReadFile(passFile)
		if err != nil {
			_ = lock.Close()
			return nil, nil, fmt.Errorf("wallet passphrase: %w", err)
		}
		pass = []byte(strings.TrimRight(string(b), "\r\n"))
	}
	if err := cli.CheckNewPassphrase(data, pass); err != nil { // finding 20
		_ = lock.Close()
		return nil, nil, err
	}
	n, err := node.NewWithConfig(data, node.Config{WalletPassphrase: pass, InsecurePlainWallet: plain, WalletReadOnly: ro})
	if err != nil {
		_ = lock.Close()
		return nil, nil, fmt.Errorf("cannot open data directory: %w", err)
	}
	if w := n.Wallet.LegacyWarning(); w != "" {
		fmt.Fprintln(os.Stderr, w)
	}
	d := cli.New(n, nil, nil)
	d.Echo = echo
	return d, lock, nil
}
