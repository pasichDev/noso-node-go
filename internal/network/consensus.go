package network

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// Consensus item indexes (nosoconsensus.pas:65-75).
const (
	CLastBlock = 2
	CHeaders   = 5
	CMNsHash   = 8
	CMNsCount  = 9
	CLBHash    = 10
	CLBTimeEnd = 12
	CSumHash   = 17
	CGVTsHash  = 18
	CCFGHash   = 19
)

// Full-hash consensus items, appended after the original 21. They carry the
// complete 128-bit identity hash of the state files, voted by the seeds
// like every other item but accepted only when more than half of ALL
// configured seeds agree. A downloaded state file is stored only if its
// full hash equals one of these, so the source of the file (any peer, even
// the one that advertises a matching hash in its PING) has no say. This
// replaces the original 5-character (20-bit) comparison that a grind can
// satisfy (docs/compatibility.md, C-03, H-06).
const (
	CFullHeaders = 21 + iota
	CFullMNs
	CFullSummary
	CFullGVTs
	CFullCFG
	CFullPSO
)

// NConsensus names the consensus items (nosoconsensus.pas:78-82).
var NConsensus = [27]string{"Resume", "Peers", "LBlock", "Pending", "Delta", "Headers", "Version",
	"UTCTime", "MNsHash", "MNsCount", "LBHash", "BestDiff", "LBTimeEnd", "LBMiner", "ChecksCount",
	"LBPoW", "LBDiff", "Summary", "GVTs", "NosoCFG", "PSOHash",
	"HeadersFull", "MNsFull", "SummaryFull", "GVTsFull", "NosoCFGFull", "PSOHashFull"}

type nodeConsensus struct {
	host   string
	port   int
	data   string
	conStr string
	block  int
	peers  int
}

// ConsensusStats mirrors the Css_* variables.
type ConsensusStats struct {
	TotalNodes, ReachedNodes, ValidNodes, Percentage int
	Completed                                        bool
}

// GetConHash mirrors nosoconsensus.pas:215-221.
func GetConHash(line string) string {
	p := func(n int64) string { return codec.Parameter(line, n) }
	return crypto.IDHash(p(2) + codec.Copy(p(5), 0, 5) + codec.Copy(p(8), 0, 5) +
		codec.Copy(p(10), 0, 5) + codec.Copy(p(17), 0, 5) + codec.Copy(p(18), 0, 5) +
		codec.Copy(p(19), 0, 5))
}

// GetConsensus mirrors GetConsensus: item i of the last computed consensus,
// "" when out of range.
func (e *Engine) GetConsensus(i int) string {
	e.consMu.Lock()
	defer e.consMu.Unlock()
	if i < 0 || i >= len(e.cons) {
		return ""
	}
	return e.cons[i]
}

// ConsStats returns the statistics of the last consensus round.
func (e *Engine) ConsStats() ConsensusStats {
	e.consMu.Lock()
	defer e.consMu.Unlock()
	return e.consStats
}

// ConsensusItems returns a copy of every consensus item.
func (e *Engine) ConsensusItems() []string {
	e.consMu.Lock()
	defer e.consMu.Unlock()
	return append([]string(nil), e.cons...)
}

// SetNodesArray mirrors SetNodesArray (nosoconsensus.pas:236-261): the seed
// list "ip;port:ip;port:" (port 8080 by default).
func (e *Engine) SetNodesArray(list string) {
	list = codec.Trim(strings.ReplaceAll(list, ":", " "))
	var arr []nodeConsensus
	seen := map[string]bool{}
	if list != "" {
		for _, item := range strings.Split(list, " ") {
			item = strings.ReplaceAll(item, ";", " ")
			nc := nodeConsensus{host: codec.Parameter(item, 0), port: int(codec.StrToIntDef(codec.Parameter(item, 1), 8080))}
			// FIX(H-04, M7): a seed listed twice counted twice in the vote.
			// "null" is the empty-field marker, not a host. A seed is a host
			// and a port, so several nodes of one machine count separately.
			if k := nc.host + ":" + codec.IntToStr(int64(nc.port)); !seen[k] && nc.host != "" && nc.host != "null" {
				seen[k] = true
				arr = append(arr, nc)
			}
		}
	}
	e.consMu.Lock()
	e.nodesArr = arr
	e.lastConsensusTime = 0
	e.consMu.Unlock()
}

// seedKey returns the configured status-signing key of a seed host.
func (e *Engine) seedKey(host string) string {
	for _, kv := range strings.Split(e.N.Options().SeedKeys, ",") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 && p[0] == host {
			return p[1]
		}
	}
	return ""
}

// checkSignedStatus verifies the SIG suffix of a seed's status reply when a
// key is configured for that seed, and returns the line without it.
// FIX(H-04): status replies were plain text from an unauthenticated socket.
func (e *Engine) checkSignedStatus(host, line string) (string, bool) {
	key := e.seedKey(host)
	i := strings.LastIndex(line, " SIG:")
	if key == "" {
		if i >= 0 {
			line = line[:i]
		}
		return line, true
	}
	if i < 0 {
		return "", false
	}
	body, sig := line[:i], line[i+5:]
	if !crypto.VerifyCanonical(key, sig, "STATUS1", body) {
		return "", false
	}
	if d := e.N.UTCTime() - codec.StrToInt64Def(codec.Parameter(body, 7), 0); d > 60 || d < -60 {
		return "", false // replayed or stale
	}
	return body, true
}

// SignedStatus returns the status line with a signature when this node holds
// a sign key.
func (e *Engine) SignedStatus() string {
	body := "NODESTATUS " + e.NodeStatusString()
	o := e.N.Options()
	if w := e.N.Wallet.At(e.N.Wallet.IndexOf(o.MNSign)); o.MNSign != "" && w.PrivateKey != "" {
		return body + " SIG:" + crypto.SignCanonical(w.PrivateKey, "STATUS1", body)
	}
	return body
}

// RequestLine mirrors RequestLineToPeer: connect, send one line, read one
// line (1 second timeouts), errors yield "".
func (e *Engine) RequestLine(host string, port int, line string) string {
	c, err := e.Dial(net.JoinHostPort(host, codec.IntToStr(int64(port))), time.Second)
	if err != nil {
		return ""
	}
	cc := NewConn(c)
	defer cc.Close()
	if cc.WriteLine(line) != nil {
		return ""
	}
	r, err := cc.ReadLine(time.Second)
	if err != nil {
		return ""
	}
	return r
}

// CalculateConsensus mirrors nosoconsensus.pas:279-412: every seed is asked
// NODESTATUS; the most common consensus hash wins and then, parameter by
// parameter, the most common value among the nodes that agree on it.
func (e *Engine) CalculateConsensus() []string {
	e.consMu.Lock()
	nodes := append([]nodeConsensus(nil), e.nodesArr...)
	e.consMu.Unlock()
	var wg sync.WaitGroup
	reached := 0
	var rm sync.Mutex
	for i := range nodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			line := e.RequestLine(nodes[i].host, nodes[i].port, "NODESTATUS")
			var sigOK bool
			if line, sigOK = e.checkSignedStatus(nodes[i].host, line); sigOK && codec.Copy(line, 1, 10) == "NODESTATUS" {
				h := GetConHash(line)
				line = strings.ReplaceAll(line, "NODESTATUS", h)
				nodes[i].data = line
				nodes[i].conStr = h
				nodes[i].peers = int(codec.StrToIntDef(codec.Parameter(line, 1), 0))
				nodes[i].block = int(codec.StrToIntDef(codec.Parameter(line, 2), 0))
				rm.Lock()
				reached++
				rm.Unlock()
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	rm.Lock()
	reachedN := reached
	rm.Unlock()

	type kv struct {
		v string
		c int
	}
	topCount := 0
	highest := func(arr []kv) string {
		max, idx := 0, 0
		for i, a := range arr {
			if a.c > max {
				max, idx = a.c, i
			}
		}
		if len(arr) == 0 {
			return ""
		}
		topCount = max
		return arr[idx].v
	}
	add := func(arr []kv, v string) []kv {
		for i := range arr {
			if arr[i].v == v {
				arr[i].c++
				return arr
			}
		}
		return append(arr, kv{v, 1})
	}
	var arr []kv
	for _, nd := range nodes {
		if p := codec.Parameter(nd.data, 0); p != "" {
			arr = add(arr, p)
		}
	}
	conHash := highest(arr)
	stats := ConsensusStats{TotalNodes: len(nodes), ReachedNodes: reachedN}
	// FIX(H-04): the winner needs more than half of ALL configured seeds, not
	// just a plurality of the ones that answered (nosoconsensus.pas:351-357).
	if topCount*2 <= len(nodes) {
		conHash = ""
	}
	if conHash == "" {
		res := make([]string, len(NConsensus))
		e.consMu.Lock()
		e.cons = res
		e.consStats = stats
		e.lastConsensusTime -= 50
		e.consMu.Unlock()
		return res
	}
	result := []string{conHash}
	valid := 0
	for param := int64(1); param < int64(len(NConsensus)); param++ {
		arr = nil
		for _, nd := range nodes {
			if codec.Parameter(nd.data, 0) == conHash {
				arr = add(arr, codec.Parameter(nd.data, param))
				if param == 1 {
					valid++
				}
			}
		}
		h := highest(arr)
		if param >= CFullHeaders && topCount*2 <= len(nodes) {
			h = "" // full hashes need a majority of all configured seeds
		}
		if h == "" && param < CFullHeaders {
			break
		}
		result = append(result, h)
	}
	for len(result) < len(NConsensus) {
		result = append(result, "")
	}
	stats.ValidNodes = valid
	if reachedN > 0 {
		stats.Percentage = valid * 100 / reachedN
	}
	stats.Completed = true
	e.consMu.Lock()
	e.cons = result
	e.consStats = stats
	e.consMu.Unlock()
	return result
}
