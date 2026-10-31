// Package cli implements the console command interpreter of the original
// node (mpparser.pas ParseCommandLine). The same dispatcher serves the
// nosocli tool, the nosod control socket and the GUI console.
package cli

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
	"github.com/pasichDev/noso-node-go/internal/rpc"
)

// HideCommands are not echoed (masterpaskalform.pas:564).
const HideCommands = "CLEAR SENDPOOLSOLUTION SENDPOOLSTEPS DELBOTS"

// Dispatcher runs console commands against a node. E and R are nil in
// offline mode (no networking): commands that need them say so.
type Dispatcher struct {
	N *node.Node
	E *network.Engine
	R *rpc.Server

	// Echo prints ">> command" before running it, like the GUI console.
	Echo bool
	// Quit is called by RESTART / shutdown style commands.
	Quit func(restart bool)
	// RPCPort/RPCSetter let the daemon change the port in use.
	mu  sync.Mutex
	out func(string)
}

// New returns a dispatcher.
func New(n *node.Node, e *network.Engine, r *rpc.Server) *Dispatcher {
	return &Dispatcher{N: n, E: e, R: r}
}

// Run executes one command line and returns everything it printed.
func (d *Dispatcher) Run(line string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	d.out = func(s string) { out = append(out, s) }
	d.exec(line)
	d.out = nil
	return out
}

// RunTo executes a command streaming its output to f.
func (d *Dispatcher) RunTo(line string, f func(string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.out = f
	d.exec(line)
	d.out = nil
}

func (d *Dispatcher) log(format string, a ...any) {
	s := format
	if len(a) > 0 {
		s = fmt.Sprintf(format, a...)
	}
	if d.out != nil {
		d.out(s)
	}
}

func (d *Dispatcher) printer() network.Printer { return func(s string) { d.log("%s", s) } }

func (d *Dispatcher) needNet() bool {
	if d.E == nil {
		d.log("This command needs a running node (nosod); offline mode only serves local data.")
		return false
	}
	return true
}

var handlers map[string]func(d *Dispatcher, line string)

// Commands returns the sorted command names (used by help and docs).
func Commands() []string {
	var names []string
	for k := range handlers {
		names = append(names, k)
	}
	sortStrings(names)
	return names
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (d *Dispatcher) exec(line string) {
	cmd := codec.Parameter(line, 0)
	up := strings.ToUpper(cmd)
	if d.Echo && !strings.Contains(HideCommands, up) {
		d.log(">> %s", line)
	}
	if up == "" {
		return
	}
	if h, ok := handlers[up]; ok {
		h(d, line)
		return
	}
	d.log("Unknown command: %s", cmd)
}
