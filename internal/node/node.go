// Package node is the Noso node engine: it owns every data file, the
// pending pool, the masternode tables and implements block construction,
// summary rebuild and order validation exactly like the Pascal units
// nosonetwork, mpblock, mpdisk, mpprotocol, mpcoin and nosomasternodes.
//
// The package performs no network I/O; internal/network drives it.
package node

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Version constants (masterpaskalform.pas:567-579, nosonetwork.pas:136-138).
const (
	MainnetVersion  = "0.4.4"
	NodeRelease     = "Ab9"
	Protocol        = 2
	VersionRequired = "0.4.4"
	BuildDate       = "September 2024"
	MaxConnections  = 99
)

// Node is the whole node state.
type Node struct {
	Lay     storage.Layout
	Summary *storage.SummaryDB
	Headers *storage.Headers
	GVTs    *storage.GVTs
	Wallet  *storage.Wallet
	CFG     *storage.CFG
	MNFile  *storage.MNFile
	PSOs    *storage.PSOs
	Blocks  *storage.Blocks
	DB      *storage.BlocksDB

	Opts   storage.Options
	optsMu sync.Mutex

	// TimeOffset mirrors NosoT_TimeOffset (seconds added to the local clock).
	timeOffset int64
	clock      func() int64 // local unix time; replaceable for tests

	mu          sync.Mutex
	myLastBlock int64
	myLastHash  string
	lastBlock   types.BlockHeader
	conStatus   int // MyConStatus 0..3
	building    int64
	undoHighest int64

	poolMu sync.Mutex
	pool   []types.Order

	mn mnState

	idsMu        sync.Mutex
	idsProcessed []string // ArrayOrderIDsProcessed

	// Hooks set by the network layer; nil in unit tests.
	Log        func(channel, msg string)
	OnNewBlock func()             // ping broadcast after a block (BuildNewBlock end)
	Broadcast  func(line string)  // OutgoingMsjsAdd
	Consensus  func(i int) string // GetConsensus(i)
	ServerOn   func() bool        // Form1.Server.Active
	ServerPort func() int         // Form1.Server.DefaultPort
	TotalConns func() int         // GetTotalConexiones

	// Statistics shown by commands.
	MontoIncoming, MontoOutgoing int64
	StartTime                    int64
}

// New opens with a clear-text wallet (tests); use NewWithConfig otherwise. It opens (and creates when missing) the data directory like
// VerifyFiles/FileStructure (mpdisk.pas:66-163).
func New(root string, fetchSeeds func() string) (*Node, error) {
	return NewWithConfig(root, Config{FetchSeeds: fetchSeeds, InsecurePlainWallet: true})
}

// Config selects how a node opens its data.
type Config struct {
	// FetchSeeds downloads the default seed list on first start (nil: none).
	FetchSeeds func() string
	// WalletPassphrase encrypts the wallet (FIX(H-10)): wallet.enc is used,
	// and a legacy wallet.pkw is migrated into it and destroyed.
	WalletPassphrase []byte
	// InsecurePlainWallet keeps the original clear-text wallet.pkw. It exists
	// for tests and must be asked for explicitly.
	InsecurePlainWallet bool
}

// NewWithConfig opens (and creates when missing) the data directory like
// VerifyFiles/FileStructure (mpdisk.pas:66-163).
func NewWithConfig(root string, cfg Config) (*Node, error) {
	fetchSeeds := cfg.FetchSeeds
	n := &Node{Lay: storage.NewLayout(root), clock: func() int64 { return time.Now().Unix() }}
	n.Opts = storage.DefaultOptions(MainnetVersion + NodeRelease)
	if n.Lay.EnsureDirs() > 0 {
		return nil, os.ErrPermission
	}
	n.StartTime = n.UTCTime()
	n.Headers = storage.OpenHeaders(n.Lay.Headers)
	if storage.Exists(n.Lay.AdvOpt) {
		_ = n.Opts.Load(n.Lay.AdvOpt)
	}
	n.MNFile = storage.OpenMNFile(n.Lay.Masternodes)
	n.GVTs = storage.OpenGVTs(n.Lay.GVTs)
	n.CFG = storage.OpenCFG(n.Lay.CFG, n.UTCTime, fetchSeeds)
	switch {
	case len(cfg.WalletPassphrase) > 0:
		w, err := storage.OpenWalletEncrypted(n.Lay.Wallet, cfg.WalletPassphrase)
		if err != nil {
			return nil, err
		}
		n.Wallet = w
	case cfg.InsecurePlainWallet:
		n.Wallet, _ = storage.OpenWallet(n.Lay.Wallet)
	default:
		return nil, ErrNoPassphrase
	}
	n.Blocks = storage.NewBlocks(n.Lay)
	n.Summary = storage.OpenSummary(n.Lay.Summary)
	if !storage.Exists(n.Lay.Summary) {
		n.Summary.CreateNew(storage.Exists(n.Lay.BlockFile(0)))
	}
	n.Summary.CreateIndex()
	if n.Opts.BlocksDB {
		n.DB = storage.OpenBlocksDB(n.Lay.BlocksDB)
	} else {
		if !storage.Exists(n.Lay.BlocksDB) {
			_ = os.WriteFile(n.Lay.BlocksDB, nil, 0o644)
		}
		n.DB = storage.OpenBlocksDB(n.Lay.BlocksDB)
		n.DB.LoadIndex() // Pascal only loads the index when BlocksDB is on; empty otherwise
	}
	n.PSOs = storage.OpenPSOs(n.Lay.PSOs)
	if !storage.Exists(n.Lay.BlockFile(0)) {
		n.CreateGenesis()
	}
	n.myLastBlock = n.Blocks.LastUpdated()
	n.Wallet.ImportFromBackup(n.Lay.RPCBakDir)
	n.UpdateMyData()
	return n, nil
}

// SaveOptions persists advopt.txt (CreateADV); an empty MNSign defaults to
// the first wallet address (mpdisk.pas:280).
func (n *Node) SaveOptions() error {
	n.optsMu.Lock()
	defer n.optsMu.Unlock()
	if n.Opts.MNSign == "" {
		n.Opts.MNSign = n.Wallet.At(0).Hash
	}
	return n.Opts.Save(n.Lay.AdvOpt)
}

// Options returns a copy of the options.
func (n *Node) Options() storage.Options {
	n.optsMu.Lock()
	defer n.optsMu.Unlock()
	return n.Opts
}

// UpdateOptions mutates the options under the lock.
func (n *Node) UpdateOptions(f func(o *storage.Options)) {
	n.optsMu.Lock()
	f(&n.Opts)
	n.optsMu.Unlock()
}

// SetClock replaces the local clock (tests, simulations).
func (n *Node) SetClock(f func() int64) { n.clock = f }

// UTCTime mirrors NosoTime.UTCTime: local unix time plus the NTP offset.
func (n *Node) UTCTime() int64 {
	return n.clock() + n.timeOffsetValue()
}

func (n *Node) timeOffsetValue() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.timeOffset
}

// SetTimeOffset stores the offset obtained from NTP.
func (n *Node) SetTimeOffset(v int64) {
	n.mu.Lock()
	n.timeOffset = v
	n.mu.Unlock()
}

// UTCTimeStr mirrors nosotime.pas:127-130.
func (n *Node) UTCTimeStr() string { return codec.IntToStr(n.UTCTime()) }

// BlockAge mirrors nosotime.pas:161-164.
func (n *Node) BlockAge() int64 { return consensus.BlockAge(n.UTCTime()) }

func (n *Node) logf(ch, msg string) {
	if n.Log != nil {
		n.Log(ch, msg)
	}
}

// MyLastBlock returns the height of the last local block.
func (n *Node) MyLastBlock() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.myLastBlock
}

// SetMyLastBlock assigns MyLastBlock (after downloads).
func (n *Node) SetMyLastBlock(v int64) {
	n.mu.Lock()
	n.myLastBlock = v
	n.mu.Unlock()
}

// MyLastBlockHash returns the MD5 of the last block file.
func (n *Node) MyLastBlockHash() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.myLastHash
}

// LastBlockData returns the header of the last block.
func (n *Node) LastBlockData() types.BlockHeader {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastBlock
}

// ConStatus returns MyConStatus (0 disconnected, 1 connecting, 2 connected,
// 3 updated).
func (n *Node) ConStatus() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.conStatus
}

// SetConStatus assigns MyConStatus.
func (n *Node) SetConStatus(v int) {
	n.mu.Lock()
	n.conStatus = v
	n.mu.Unlock()
}

// Building returns the block number under construction (0 when idle).
func (n *Node) Building() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.building
}

// UpdateMyData mirrors NosoNetwork.UpdateMyData (nosonetwork.pas:698-707).
func (n *Node) UpdateMyData() {
	n.mu.Lock()
	last := n.myLastBlock
	n.mu.Unlock()
	hash := crypto.IDHashFile(n.Lay.BlockFile(last))
	hdr := n.Blocks.Header(last)
	n.mu.Lock()
	n.myLastHash = hash
	n.lastBlock = hdr
	n.mu.Unlock()
	n.Headers.SetHash()
}

// IsSeedNode and friends are thin wrappers used by the network layer.
func (n *Node) IsSeedNode(ip string) bool { return n.CFG.IsSeedNode(ip) }

// ClearReceivedOrderIDs mirrors ClearReceivedOrdersIDs (mpred.pas:1127).
func (n *Node) ClearReceivedOrderIDs() {
	n.idsMu.Lock()
	n.idsProcessed = nil
	n.idsMu.Unlock()
}

// OrderIDAlreadyProcessed mirrors IsOrderIDAlreadyProcessed
// (mpprotocol.pas:813-834): parameter 7 of the line is remembered.
func (n *Node) OrderIDAlreadyProcessed(line string) bool {
	id := codec.Parameter(line, 7)
	n.idsMu.Lock()
	defer n.idsMu.Unlock()
	for _, x := range n.idsProcessed {
		if x == id {
			return true
		}
	}
	n.idsProcessed = append(n.idsProcessed, id)
	return false
}

// TimeAgo mirrors TimeSinceStamp (nosotime.pas:147-158).
func (n *Node) TimeAgo(stamp int64) string {
	e := n.UTCTime() - stamp
	switch {
	case e/60 < 1:
		return codec.IntToStr(e) + "s"
	case e/3600 < 1:
		return codec.IntToStr(e/60) + "m"
	case e/86400 < 1:
		return codec.IntToStr(e/3600) + "h"
	case e/2592000 < 1:
		return codec.IntToStr(e/86400) + "d"
	case e/31536000 < 1:
		return codec.IntToStr(e/2592000) + "M"
	}
	return codec.IntToStr(e/31536000) + " Y"
}

// StorageOptions re-exports storage.Options for callers that only import
// the node package.
type StorageOptions = storage.Options

// ErrNoPassphrase is returned when no wallet passphrase was given and the
// clear-text wallet was not explicitly allowed.
var ErrNoPassphrase = errors.New("a wallet passphrase is required (or explicitly allow the insecure plain wallet)")

// EnsureRPCTokens creates random RPC tokens on first use and stores them in
// advopt.txt (mode 0600). FIX(H-09): the original shipped the password
// "default" and never checked it.
func (n *Node) EnsureRPCTokens() {
	changed := false
	n.UpdateOptions(func(o *storage.Options) {
		if o.RPCToken == "" {
			o.RPCToken, changed = randomToken(), true
		}
		if o.RPCSpendToken == "" {
			o.RPCSpendToken, changed = randomToken(), true
		}
	})
	if changed {
		_ = n.SaveOptions()
	}
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
