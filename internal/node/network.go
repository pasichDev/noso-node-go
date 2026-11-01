package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// NetworkFile is the file of a data directory that holds the settings every
// node of one network must share. `nosod init-network` writes it. A node
// without it uses the default chain id and the strict masternode address rule.
const NetworkFile = "network.txt"

// NetworkConfig is the content of the network file.
type NetworkConfig struct {
	// ChainID is mixed into every signed order, so an order signed on one
	// network is not valid on another (FIX(F-18)).
	ChainID string
	// LocalMasternodes lets masternodes announce loopback and private
	// addresses. It is a network rule: the same on every node, so it comes
	// only from this file, never from a flag or an option.
	LocalMasternodes bool
}

// NewNetworkConfig returns a configuration with a fresh random chain id.
func NewNetworkConfig(localMasternodes bool) (NetworkConfig, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return NetworkConfig{}, err
	}
	return NetworkConfig{ChainID: "noso-net-" + hex.EncodeToString(b[:]), LocalMasternodes: localMasternodes}, nil
}

func validChainID(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}

// Text is the file content.
func (c NetworkConfig) Text() string {
	return "# Settings shared by every node of this network. Do not edit: a node with other\n" +
		"# values belongs to another network and refuses this chain.\n" +
		"chain_id " + c.ChainID + "\n" +
		fmt.Sprintf("local_masternodes %v\n", c.LocalMasternodes)
}

// Digest is what the blocks commit to: a hash of the canonical form, so
// comments and spacing in the file do not matter but every value does.
func (c NetworkConfig) Digest() string {
	return crypto.SHA256String(fmt.Sprintf("NETWORK1\nchain_id=%s\nlocal_masternodes=%v\n", c.ChainID, c.LocalMasternodes))
}

// ParseNetworkConfig reads the file text strictly: both keys exactly once, no
// other key.
func ParseNetworkConfig(text string) (NetworkConfig, error) {
	var c NetworkConfig
	seen := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 2 {
			return NetworkConfig{}, fmt.Errorf("network file: bad line %q", l)
		}
		if seen[f[0]] {
			return NetworkConfig{}, fmt.Errorf("network file: %s given twice", f[0])
		}
		seen[f[0]] = true
		switch f[0] {
		case "chain_id":
			if !validChainID(f[1]) {
				return NetworkConfig{}, errors.New("network file: chain_id must be 8 to 64 characters of letters, digits, '-', '.', '_'")
			}
			c.ChainID = f[1]
		case "local_masternodes":
			switch f[1] {
			case "true":
				c.LocalMasternodes = true
			case "false":
			default:
				return NetworkConfig{}, errors.New("network file: local_masternodes must be true or false")
			}
		default:
			return NetworkConfig{}, fmt.Errorf("network file: unknown key %q", f[0])
		}
	}
	if !seen["chain_id"] || !seen["local_masternodes"] {
		return NetworkConfig{}, errors.New("network file: chain_id and local_masternodes are both required")
	}
	return c, nil
}

// WriteNetworkConfig writes the network file into a data directory.
func WriteNetworkConfig(root string, c NetworkConfig) error {
	if !validChainID(c.ChainID) {
		return errors.New("invalid chain id")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	return storage.WriteFileAtomic(filepath.Join(root, NetworkFile), []byte(c.Text()))
}

// loadNetwork reads the network file. A missing file means the default
// network; a file that cannot be read or parsed is a hard error, so a node
// never falls back to the default by accident.
func (n *Node) loadNetwork() error {
	raw, err := os.ReadFile(filepath.Join(n.Lay.Root, NetworkFile))
	if errors.Is(err, os.ErrNotExist) {
		n.network, n.hasNetwork = NetworkConfig{ChainID: crypto.ChainID}, false
		return nil
	}
	if err != nil {
		return err
	}
	c, err := ParseNetworkConfig(string(raw))
	if err != nil {
		return err
	}
	n.network, n.hasNetwork = c, true
	return nil
}

// ChainID is the chain id this node signs and verifies orders under.
func (n *Node) ChainID() string { return n.network.ChainID }

// LocalMasternodes reports the network rule that masternodes may use loopback
// and private addresses.
func (n *Node) LocalMasternodes() bool { return n.network.LocalMasternodes }

// chainDigestFor is the digest every block commits to in its Solution field:
// the proposer list and, when the data directory has a network file, that
// file as well, so nodes with different settings cannot share a chain. Without
// a network file it is the proposer digest alone.
func (n *Node) chainDigestFor(keys []string) string {
	d := proposersDigest(keys)
	if !n.hasNetwork {
		return d
	}
	return crypto.SHA256String("CHAIN2\n" + d + "\n" + n.network.Digest())
}

func (n *Node) chainDigest() string { return n.chainDigestFor(n.Proposers()) }
