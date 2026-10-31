package node

import (
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// MNode is TMNode (nosomasternodes.pas:22-32). Strings carry the
// ShortString capacities of the record.
type MNode struct {
	IP          string // String[15]
	Port        int32
	Sign        string // String[40]
	Fund        string // String[40]
	First       int32
	Last        int32
	Total       int32
	Validations int32
	Hash        string // String[32]
}

// MNCheck is TMNCheck, a masternode verification report.
type MNCheck struct {
	ValidatorIP string
	Block       int32
	SignAddress string
	PubKey      string
	ValidNodes  string
	Signature   string
}

type mnState struct {
	mu        sync.Mutex
	list      []MNode
	checks    []MNCheck
	ipsProc   []string
	waiting   []string
	received  []string
	verified  string // VerifiedNodes of the running verification
	verifying int
}

// MNsListLen mirrors GetMNsListLength.
func (n *Node) MNsListLen() int {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	return len(n.mn.list)
}

// MNsList returns a copy of the reported masternodes.
func (n *Node) MNsList() []MNode {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	return append([]MNode(nil), n.mn.list...)
}

// ClearMNsList mirrors ClearMNsList (also resets the processed-IP list).
func (n *Node) ClearMNsList() {
	n.mn.mu.Lock()
	n.mn.list = nil
	n.mn.ipsProc = nil
	n.mn.mu.Unlock()
}

// IPMNAlreadyProcessed mirrors IsIPMNAlreadyProcessed (parameter 5).
func (n *Node) IPMNAlreadyProcessed(line string) bool {
	ip := codec.Parameter(line, 5)
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, x := range n.mn.ipsProc {
		if x == ip {
			return true
		}
	}
	n.mn.ipsProc = append(n.mn.ipsProc, ip)
	return false
}

// ClearMNIPProcessed mirrors ClearMNIPProcessed.
func (n *Node) ClearMNIPProcessed() {
	n.mn.mu.Lock()
	n.mn.ipsProc = nil
	n.mn.mu.Unlock()
}

// MyMNListed mirrors IsMyMNListed.
func (n *Node) MyMNListed(ip string) bool {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, m := range n.mn.list {
		if m.IP == ip {
			return true
		}
	}
	return false
}

// IsLegitNewNode mirrors nosomasternodes.pas:374-399. COMPAT: with an
// empty list every report is accepted without checking funds, and the
// balance/validation tests run once per existing entry.
func (n *Node) IsLegitNewNode(m MNode, block int64) bool {
	n.mn.mu.Lock()
	list := append([]MNode(nil), n.mn.list...)
	n.mn.mu.Unlock()
	for _, e := range list {
		if m.IP == e.IP || m.Sign == e.Sign || m.Fund == e.Fund ||
			n.Summary.BalanceIndexed(m.Fund) < consensus.GetStackRequired(block+1) ||
			m.Validations != 0 {
			return false
		}
	}
	return true
}

// ParseMNode mirrors GetMNodeFromString (nosomasternodes.pas:447-476).
func ParseMNode(s string) (MNode, bool) {
	p := func(i int64) string { return codec.Parameter(s, i) }
	m := MNode{
		IP:          codec.Truncate(p(1), 15),
		Port:        int32(codec.StrToIntDef(p(2), -1)),
		Sign:        codec.Truncate(p(3), 40),
		Fund:        codec.Truncate(p(4), 40),
		First:       int32(codec.StrToIntDef(p(5), -1)),
		Last:        int32(codec.StrToIntDef(p(6), -1)),
		Total:       int32(codec.StrToIntDef(p(7), -1)),
		Validations: int32(codec.StrToIntDef(p(8), -1)),
		Hash:        codec.Truncate(p(9), 32),
	}
	switch {
	case !codec.IsValidIP(m.IP):
		return m, false
	case m.Port < 0 || m.Port > 65535:
	case !crypto.IsValidHashAddress(m.Sign):
	case !crypto.IsValidHashAddress(m.Fund):
	case m.First < 0, m.Last < 0, m.Total < 0, m.Validations < 0:
	case m.Hash != crypto.MD5String(m.IP+codec.IntToStr(int64(m.Port))+m.Sign+m.Fund):
	default:
		return m, true
	}
	return m, false
}

// StringFromMN mirrors GetStringFromMN.
func StringFromMN(m MNode) string {
	i := func(v int32) string { return codec.IntToStr(int64(v)) }
	return m.IP + " " + i(m.Port) + " " + m.Sign + " " + m.Fund + " " + i(m.First) + " " +
		i(m.Last) + " " + i(m.Total) + " " + i(m.Validations) + " " + m.Hash
}

// CheckMNReport mirrors nosomasternodes.pas:401-444: a valid, legit report
// is inserted ordered by IP and its "$MNREPO ..." text returned for
// re-broadcast.
func (n *Node) CheckMNReport(line string, block int64) string {
	p := strings.IndexByte(line, '$')
	if p < 0 {
		p = 0
	}
	info := line[p:]
	m, ok := ParseMNode(info)
	if !ok || !n.IsLegitNewNode(m, block) {
		return ""
	}
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	pos := len(n.mn.list)
	for i, e := range n.mn.list {
		if m.IP < e.IP {
			pos = i
			break
		}
	}
	n.mn.list = append(n.mn.list, MNode{})
	copy(n.mn.list[pos+1:], n.mn.list[pos:])
	n.mn.list[pos] = m
	return info
}

// MNReportString mirrors GetMNReportString (nosomasternodes.pas:165-171).
func (n *Node) MNReportString(block int64) string {
	o := n.Options()
	b := codec.IntToStr(block)
	return o.MNIP + " " + o.MNPort + " " + o.MNSign + " " + o.MNFunds + " " + b + " " + b + " 0 0 " +
		crypto.MD5String(o.MNIP+o.MNPort+o.MNSign+o.MNFunds)
}

// MNsAddresses mirrors GetMNsAddresses (nosomasternodes.pas:507-528).
// COMPAT: with zero checks MinValidations is -1, so every reported node is
// listed; and the final blank is chopped, so with no node the text is just
// the block number.
func (n *Node) MNsAddresses(block int64) string {
	minV := int32(len(n.mn.checksSnapshot(n))/2 - 1)
	res := codec.IntToStr(block) + " "
	n.mn.mu.Lock()
	list := append([]MNode(nil), n.mn.list...)
	n.mn.mu.Unlock()
	for _, m := range list {
		if m.Validations >= minV {
			res += m.IP + ";" + codec.IntToStr(int64(m.Port)) + ":" + m.Fund +
				n.MNFile.AgeCount(m.IP, int(m.Port), m.Fund) + " "
		}
	}
	return res[:len(res)-1]
}

func (s *mnState) checksSnapshot(_ *Node) []MNCheck {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]MNCheck(nil), s.checks...)
}

// CreditMNVerifications mirrors nosomasternodes.pas:530-578: every IP
// named in a validator's report gains one validation.
func (n *Node) CreditMNVerifications() {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, c := range n.mn.checks {
		nodes := strings.ReplaceAll(c.ValidNodes, ":", " ")
		for i := int64(0); ; i++ {
			ip := strings.ReplaceAll(codec.Parameter(nodes, i), ";", " ")
			ip = codec.Parameter(ip, 0)
			if ip == "" {
				break
			}
			for j := range n.mn.list {
				if n.mn.list[j].IP == ip {
					n.mn.list[j].Validations++
					break
				}
			}
		}
	}
}

// ChecksCount mirrors GetMNsChecksCount.
func (n *Node) ChecksCount() int {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	return len(n.mn.checks)
}

// Checks returns a copy of the validation reports.
func (n *Node) Checks() []MNCheck {
	return n.mn.checksSnapshot(n)
}

// ClearMNsChecks mirrors ClearMNsChecks.
func (n *Node) ClearMNsChecks() {
	n.mn.mu.Lock()
	n.mn.checks = nil
	n.mn.mu.Unlock()
}

// ParseMNCheck mirrors GetMNCheckFromString (parameters 5..10).
func ParseMNCheck(s string) MNCheck {
	p := func(i int64) string { return codec.Parameter(s, i) }
	return MNCheck{p(5), int32(codec.StrToIntDef(p(6), 0)), p(7), p(8), p(9), p(10)}
}

// StringFromMNCheck mirrors GetStringFromMNCheck.
func StringFromMNCheck(c MNCheck) string {
	return c.ValidatorIP + " " + codec.IntToStr(int64(c.Block)) + " " + c.SignAddress + " " +
		c.PubKey + " " + c.ValidNodes + " " + c.Signature
}

// CheckExists mirrors MnsCheckExists.
func (n *Node) CheckExists(ip string) bool {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, c := range n.mn.checks {
		if c.ValidatorIP == ip {
			return true
		}
	}
	return false
}

// MyCheckDone mirrors IsMyMNCheckDone.
func (n *Node) MyCheckDone() bool { return n.CheckExists(n.Options().MNIP) }

// ValidNodesInCheck mirrors GetValidNodesCountOnCheck.
func ValidNodesInCheck(s string) int {
	s = strings.ReplaceAll(s, ":", " ")
	c := 0
	for i := int64(0); codec.Parameter(s, i) != ""; i++ {
		c++
	}
	return c
}

// IsValidator mirrors nosonetwork.pas:709-713: only seed nodes validate.
func (n *Node) IsValidator(ip string) bool { return n.IsSeedNode(ip) }

// ValidateMNCheck mirrors nosonetwork.pas:716-739; the report text
// ("$MNCHECK ...") is returned on success, "" otherwise. The code paths
// overwrite each other like in Pascal (the last failing test wins; any
// non-zero rejects).
func (n *Node) ValidateMNCheck(line string) string {
	p := strings.IndexByte(line, '$')
	if p < 0 {
		p = 0
	}
	info := line[p:]
	c := ParseMNCheck(line)
	if n.CheckExists(c.ValidatorIP) {
		return ""
	}
	bad := !n.IsValidator(c.ValidatorIP) || int64(c.Block) != n.MyLastBlock() ||
		crypto.GetAddressFromPublicKey(c.PubKey, 0) != c.SignAddress ||
		!crypto.VerifySignedString(c.ValidNodes, c.Signature, c.PubKey)
	if bad {
		return ""
	}
	n.mn.mu.Lock()
	n.mn.checks = append(n.mn.checks, c)
	n.mn.mu.Unlock()
	return info
}

// AddCheck appends a locally produced report.
func (n *Node) AddCheck(c MNCheck) {
	n.mn.mu.Lock()
	n.mn.checks = append(n.mn.checks, c)
	n.mn.mu.Unlock()
}

// Received/waiting queues (nosomasternodes.pas:723-790).

// MNIPReceived mirrors IsMNIPReceived (parameter 5, remembered when new).
func (n *Node) MNIPReceived(line string) bool {
	ip := codec.Parameter(line, 5)
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, x := range n.mn.received {
		if x == ip {
			return true
		}
	}
	n.mn.received = append(n.mn.received, ip)
	return false
}

// ClearReceivedMNs mirrors ClearReceivedMNs.
func (n *Node) ClearReceivedMNs() {
	n.mn.mu.Lock()
	n.mn.received = nil
	n.mn.mu.Unlock()
}

// AddWaitingMN mirrors AddWaitingMNs.
func (n *Node) AddWaitingMN(line string) {
	if n.MNIPReceived(line) {
		return
	}
	n.mn.mu.Lock()
	n.mn.waiting = append(n.mn.waiting, line)
	n.mn.mu.Unlock()
}

// WaitingMNsLen mirrors LengthWaitingMNs.
func (n *Node) WaitingMNsLen() int {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	return len(n.mn.waiting)
}

// PopWaitingMN mirrors GetWaitingMNs.
func (n *Node) PopWaitingMN() string {
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	if len(n.mn.waiting) == 0 {
		return ""
	}
	s := n.mn.waiting[0]
	n.mn.waiting = n.mn.waiting[1:]
	return s
}

// SyncTus mirrors GetSyncTus (nosonetwork.pas:546-556).
func (n *Node) SyncTus() string {
	return codec.IntToStr(n.MyLastBlock()) + codec.Copy(n.Headers.Hash(), 1, 3) +
		codec.Copy(n.Summary.Hash(), 1, 3) + codec.Copy(n.MyLastBlockHash(), 1, 3)
}

// IsAllSynced mirrors nosonetwork.pas:532-544.
func (n *Node) IsAllSynced() int {
	r := 0
	cons := func(i int) string {
		if n.Consensus == nil {
			return ""
		}
		return n.Consensus(i)
	}
	if n.MyLastBlock() != codec.StrToIntDef(cons(2), 0) {
		r = 1
	}
	if n.MyLastBlockHash() != cons(10) {
		r = 2
	}
	if codec.Copy(n.Summary.Hash(), 1, 5) != cons(17) {
		r = 3
	}
	if codec.Copy(n.Headers.Hash(), 1, 5) != cons(5) {
		r = 4
	}
	return r
}

// VerificationLine mirrors GetVerificationMNLine (nosonetwork.pas:522-530).
func (n *Node) VerificationLine(toIP string) string {
	if n.IsAllSynced() == 0 {
		o := n.Options()
		return "True " + n.SyncTus() + " " + o.MNFunds + " " + toIP + " " + o.MNSign
	}
	return "False"
}
