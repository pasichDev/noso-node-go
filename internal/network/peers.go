package network

import (
	"sync"
	"sync/atomic"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// Peer is Tconectiondata (nosonetwork.pas:30-57): the state kept about one
// connection slot. Strings carry the ShortString capacities of the record.
type Peer struct {
	Autentic      bool
	Connections   int
	Tipo          string // "", "RES", "SER" (we dialled) or "CLI" (they dialled)
	IP            string
	LastPing      string
	LastBlock     string
	LastBlockHash string
	SumarioHash   string
	Pending       int
	Protocol      int
	Version       string
	ListeningPort int
	Offset        int64
	ResumenHash   string
	ConexStatus   int
	IsBusy        bool
	MNsHash       string
	MNsCount      int
	BestHashDiff  string
	MNChecksCount int
	GVTsHash      string
	CFGHash       string
	MerkleHash    string
	PSOHash       string
}

type slot struct {
	p        Peer
	conn     *Conn
	out      chan string
	incoming []string
	inBytes  int // size of the queued incoming lines
	sending  atomic.Int32
	closed   chan struct{}
	once     sync.Once
}

// peerTable is the Conexiones array (1..99).
type peerTable struct {
	mu    sync.Mutex
	slots [MaxConnections + 1]*slot
}

// MaxConnections mirrors MaxConecciones.
const MaxConnections = 99

func (t *peerTable) get(i int) Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i < 1 || i > MaxConnections || t.slots[i] == nil {
		return Peer{}
	}
	return t.slots[i].p
}

func (t *peerTable) set(i int, p Peer) {
	t.mu.Lock()
	if i >= 1 && i <= MaxConnections && t.slots[i] != nil {
		t.slots[i].p = p
	}
	t.mu.Unlock()
}

// GetSlotFromIP mirrors mpred.pas:61-74.
func (e *Engine) GetSlotFromIP(ip string) int {
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	for i := 1; i <= MaxConnections; i++ {
		if s := e.peers.slots[i]; s != nil && s.p.IP == ip {
			return i
		}
	}
	return 0
}

// Peer returns a copy of the slot data (GetConexIndex).
func (e *Engine) Peer(i int) Peer { return e.peers.get(i) }

// SaveConnection mirrors SaveConection (mpred.pas:116-158). A slot of -1
// picks the first free one; 0 is returned when the table is full.
func (e *Engine) SaveConnection(tipo, ip string, conn *Conn, to int) int {
	p := Peer{Tipo: tipo, IP: codec.Truncate(ip, 20), LastPing: e.N.UTCTimeStr(), LastBlock: "0",
		ListeningPort: -1}
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	mk := func() *slot {
		return &slot{p: p, conn: conn, out: make(chan string, 4096), closed: make(chan struct{})}
	}
	if to >= 1 {
		e.peers.slots[to] = mk()
		return to
	}
	// FIX(finding 17): the duplicate check is made under the same lock as
	// the insert; two simultaneous connections from one IP cannot both pass.
	for i := 1; i <= MaxConnections; i++ {
		if s := e.peers.slots[i]; s != nil && s.p.Tipo != "" && s.p.IP == p.IP && tipo == "CLI" {
			return 0
		}
	}
	for i := 1; i <= MaxConnections; i++ {
		if s := e.peers.slots[i]; s == nil || s.p.Tipo == "" {
			e.peers.slots[i] = mk()
			return i
		}
	}
	return 0
}

// ReserveSlot mirrors ReserveSlot: first free slot marked "RES".
func (e *Engine) ReserveSlot() int {
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	for i := 1; i <= MaxConnections; i++ {
		if s := e.peers.slots[i]; s == nil || s.p.Tipo == "" {
			e.peers.slots[i] = &slot{p: Peer{Tipo: "RES"}, out: make(chan string, 4096), closed: make(chan struct{})}
			return i
		}
	}
	return 0
}

// CloseSlot mirrors CloseSlot (nosonetwork.pas:651-673).
func (e *Engine) CloseSlot(i int) {
	if i < 1 || i > MaxConnections {
		return
	}
	e.peers.mu.Lock()
	s := e.peers.slots[i]
	e.peers.slots[i] = nil
	e.peers.mu.Unlock()
	if s == nil {
		return
	}
	e.forgetSlot(s, i)
	s.once.Do(func() {
		close(s.closed)
		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

// IsSlotConnected mirrors IsSlotConnected.
func (e *Engine) IsSlotConnected(i int) bool {
	t := e.peers.get(i).Tipo
	return t == "SER" || t == "CLI"
}

// TotalConnections mirrors GetTotalConexiones.
func (e *Engine) TotalConnections() int {
	c := 0
	for i := 1; i <= MaxConnections; i++ {
		if e.IsSlotConnected(i) {
			c++
		}
	}
	return c
}

// Incoming/Outgoing counters (mpred.pas:793-815).
func (e *Engine) countTipo(t string) int {
	c := 0
	for i := 1; i <= MaxConnections; i++ {
		if e.peers.get(i).Tipo == t {
			c++
		}
	}
	return c
}

// OutgoingConnections counts "SER" slots.
func (e *Engine) OutgoingConnections() int { return e.countTipo("SER") }

// IncomingConnections counts "CLI" slots.
func (e *Engine) IncomingConnections() int { return e.countTipo("CLI") }

// TextToSlot queues a line for one slot (TextToSlot, nosonetwork.pas:584).
func (e *Engine) TextToSlot(i int, line string) {
	if i < 1 || i > MaxConnections {
		return
	}
	e.peers.mu.Lock()
	s := e.peers.slots[i]
	e.peers.mu.Unlock()
	if s == nil {
		return
	}
	select {
	case s.out <- line:
	default: // queue full: drop (hardening against unbounded memory)
	}
}

// PTCSendLine mirrors PTC_SendLine (mpprotocol.pas:304-339).
func (e *Engine) PTCSendLine(i int, msg string) {
	if i >= 1 && i <= MaxConnections {
		if t := e.peers.get(i).Tipo; t == "CLI" || t == "SER" {
			e.TextToSlot(i, msg)
		}
	}
}

// OutgoingAdd mirrors OutgoingMsjsAdd: the line is sent to every connected
// slot (TThreadSendOutMsjs).
func (e *Engine) OutgoingAdd(line string) {
	for i := 1; i <= MaxConnections; i++ {
		if e.IsSlotConnected(i) {
			e.PTCSendLine(i, line)
		}
	}
}

// slotObj returns the slot object of a number, nil when empty.
func (e *Engine) slotObj(i int) *slot {
	if i < 1 || i > MaxConnections {
		return nil
	}
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	return e.peers.slots[i]
}

// addIncoming queues a received line; it reports false when the queue of
// that slot is over its count or byte bound (M-07).
func (e *Engine) addIncoming(i int, line string) bool {
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	s := e.peers.slots[i]
	if s == nil {
		return true
	}
	if len(s.incoming) >= 10000 || s.inBytes+len(line) > maxIncomingBytes {
		return false
	}
	s.incoming = append(s.incoming, line)
	s.inBytes += len(line)
	return true
}

func (e *Engine) popIncoming(i int) (string, bool) {
	e.peers.mu.Lock()
	defer e.peers.mu.Unlock()
	s := e.peers.slots[i]
	if s == nil || len(s.incoming) == 0 {
		return "", false
	}
	l := s.incoming[0]
	s.incoming = s.incoming[1:]
	s.inBytes -= len(l)
	return l, true
}

func (e *Engine) setBusy(i int, v bool) {
	e.peers.mu.Lock()
	if s := e.peers.slots[i]; s != nil {
		s.p.IsBusy = v
	}
	e.peers.mu.Unlock()
}

func (e *Engine) setLastPing(i int, v string) {
	e.peers.mu.Lock()
	if s := e.peers.slots[i]; s != nil {
		s.p.LastPing = v
	}
	e.peers.mu.Unlock()
}

// ProcessPing mirrors nosonetwork.pas:438-471. Fields of the PING/PONG
// line (1-based after the header): 5 peers, 6 last block, 7 block hash,
// 8 summary hash, 9 pending, 10 headers hash, 11 status, 12 port, 13 MNs
// hash, 14 MNs count, 15 "null", 16 checks, 17 GVTs, 18 CFG, 19 PSOs.
func (e *Engine) ProcessPing(line string, i int, reply bool) {
	g := func(n int64) string { return codec.Parameter(line, n) }
	lastBlock := codec.Truncate(g(6), 15)
	lastBlockHash := codec.Truncate(g(7), 64)
	sumHash := codec.Truncate(g(8), 64)
	resumenHash := codec.Truncate(g(10), 64)
	mnsHash := codec.Truncate(g(13), 5)
	gvtsHash := codec.Truncate(g(17), 32)
	cfgHash := codec.Truncate(g(18), 32)
	merkle := crypto.IDHash(lastBlock + codec.Copy(resumenHash, 0, 5) + codec.Copy(mnsHash, 0, 5) +
		codec.Copy(lastBlockHash, 0, 5) + codec.Copy(sumHash, 0, 5) +
		codec.Copy(gvtsHash, 0, 5) + codec.Copy(cfgHash, 0, 5))
	now := e.N.UTCTimeStr()
	offset := codec.StrToInt64Def(g(3), e.N.UTCTime()) - e.N.UTCTime()
	// FIX(finding 17): the fields are written into the slot under the table
	// lock instead of copying the whole Peer out and back, which could
	// overwrite IsBusy or LastPing set meanwhile by the slot's reader.
	e.peers.mu.Lock()
	if i < 1 || i > MaxConnections || e.peers.slots[i] == nil || e.peers.slots[i].p.Tipo == "" {
		e.peers.mu.Unlock()
		return
	}
	p := &e.peers.slots[i].p
	p.Autentic = true
	p.Protocol = int(codec.StrToIntDef(g(1), 0))
	p.Version = codec.Truncate(g(2), 8)
	p.Offset = offset
	p.Connections = int(codec.StrToIntDef(g(5), 0))
	p.LastBlock = lastBlock
	p.LastBlockHash = lastBlockHash
	p.SumarioHash = sumHash
	p.Pending = int(codec.StrToIntDef(g(9), 0))
	p.ResumenHash = resumenHash
	p.ConexStatus = int(codec.StrToIntDef(g(11), 0))
	p.ListeningPort = int(codec.StrToIntDef(g(12), -1))
	p.MNsHash = mnsHash
	p.MNsCount = int(codec.StrToIntDef(g(14), 0))
	p.BestHashDiff = "null"
	p.MNChecksCount = int(codec.StrToIntDef(g(16), 0))
	p.LastPing = now
	p.GVTsHash = gvtsHash
	p.CFGHash = cfgHash
	p.PSOHash = codec.Truncate(g(19), 32)
	p.MerkleHash = merkle
	e.peers.mu.Unlock()
	if reply {
		e.TextToSlot(i, e.ProtocolLine(4))
	}
}

// SyncedConnections mirrors GetTotalSyncedConnections (mpred.pas:403-410).
func (e *Engine) SyncedConnections() int {
	c := 0
	cons0 := e.GetConsensus(0)
	if cons0 == "" {
		return 0 // no consensus: nothing is synced (an empty hash equals an empty slot's)
	}
	for i := 1; i <= MaxConnections; i++ {
		if e.IsSlotConnected(i) && e.peers.get(i).MerkleHash == cons0 {
			c++
		}
	}
	return c
}

// ValidSlotForSeed mirrors GetValidSlotForSeed (mpred.pas:817-835): a
// rotating scan for a slot whose Merkle hash equals consensus item 0.
func (e *Engine) ValidSlotForSeed() (int, bool) {
	cons0 := e.GetConsensus(0)
	if cons0 == "" {
		return 0, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for c := 0; c < MaxConnections; c++ {
		e.slotCount++
		if e.slotCount > MaxConnections {
			e.slotCount = 1
		}
		if e.IsSlotConnected(e.slotCount) && e.peers.get(e.slotCount).MerkleHash == cons0 {
			return e.slotCount, true
		}
	}
	return 0, false
}
