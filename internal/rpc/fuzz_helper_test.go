package rpc

import (
	"os"
	"path/filepath"

	"github.com/pasichDev/noso-node-go/internal/network"
	"github.com/pasichDev/noso-node-go/internal/node"
)

func newServerFuzz() *Server {
	dir, _ := os.MkdirTemp("", "rpcfuzz")
	n, err := node.New(filepath.Join(dir, "NOSODATA"), nil)
	if err != nil {
		panic(err)
	}
	return New(network.NewEngine(n))
}
