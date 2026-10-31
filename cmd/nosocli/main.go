// Command nosocli runs the console commands of the Noso node from the
// shell. With a running nosod it talks to it over the control socket in the
// data directory; otherwise it opens the data directory itself in offline
// mode (read-only style commands and wallet management).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/cli"
	"github.com/pasichDev/noso-node-go/internal/control"
	"github.com/pasichDev/noso-node-go/internal/node"
)

func main() {
	data := flag.String("data", "NOSODATA", "data directory")
	list := flag.Bool("list", false, "list the supported commands")
	echo := flag.Bool("echo", false, "echo the command before running it")
	flag.Parse()
	if *list {
		for _, c := range cli.Commands() {
			fmt.Println(strings.ToLower(c))
		}
		return
	}
	run := func(line string) {
		if err := control.Call(control.SocketPath(*data), line, os.Stdout); err == nil {
			return
		}
		n, err := node.New(*data, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot open data directory:", err)
			os.Exit(1)
		}
		d := cli.New(n, nil, nil)
		d.Echo = *echo
		d.RunTo(line, func(s string) { fmt.Println(s) })
	}
	if flag.NArg() > 0 {
		run(strings.Join(flag.Args(), " "))
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "exit" || l == "quit" {
			return
		}
		if l != "" {
			run(l)
		}
		fmt.Print("> ")
	}
}
