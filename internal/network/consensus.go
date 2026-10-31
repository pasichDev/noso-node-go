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

// NConsensus names the consensus items (nosoconsensus.pas:78-82).
var NConsensus = [21]string{"Resume", "Peers", "LBlock", "Pending", "Delta", "Headers", "Version",
	"UTCTime", "MNsHash", "MNsCount", "LBHash", "BestDiff", "LBTimeEnd", "LBMiner", "ChecksCount",
	"LBPoW", "LBDiff", "Summary", "GVTs", "NosoCFG", "PSOHash"}

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
	return crypto.MD5String(p(2) + codec.Copy(p(5), 0, 5) + codec.Copy(p(8), 0, 5) +
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
	if list != "" {
		for _, item := range strings.Split(list, " ") {
			item = strings.ReplaceAll(item, ";", " ")
			arr = append(arr, nodeConsensus{host: codec.Parameter(item, 0),
				port: int(codec.StrToIntDef(codec.Parameter(item, 1), 8080))})
		}
	}
	e.consMu.Lock()
	e.nodesArr = arr
	e.consMu.Unlock()
	e.lastConsensusTime = 0
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
			if codec.Copy(line, 1, 10) == "NODESTATUS" {
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
	if conHash == "" {
		res := make([]string, len(NConsensus))
		e.consMu.Lock()
		e.cons = res
		e.ConsStats = stats
		e.consMu.Unlock()
		e.lastConsensusTime -= 50
		return res
	}
	result := []string{conHash}
	valid := 0
	for param := int64(1); ; param++ {
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
		if h == "" {
			break
		}
		result = append(result, h)
	}
	stats.ValidNodes = valid
	if reachedN > 0 {
		stats.Percentage = valid * 100 / reachedN
	}
	stats.Completed = true
	e.consMu.Lock()
	e.cons = result
	e.ConsStats = stats
	e.consMu.Unlock()
	return result
}
