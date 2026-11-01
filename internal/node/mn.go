package node

import (
	"os"
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
	// FIX(H-01): the fund owner's public key and signature over the report.
	Pub string
	Sig string
	// FIX(H-01): a cold-funds masternode. SignPub is the public key of the
	// sign address; Deleg is the funds key's one-time signature binding that
	// sign address to the funds address. Sig is then made by the sign key.
	SignPub string
	Deleg   string
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

// IPMNAlreadyProcessed mirrors IsIPMNAlreadyProcessed (parameter 5). FIX(F-5):
// it only asks. The IP is recorded by MarkIPMNProcessed once the report has
// answered its MNVER challenge; recording it before let a report that named
// another node's IP, and then failed the challenge, take that node's slot.
func (n *Node) IPMNAlreadyProcessed(line string) bool {
	ip := codec.Parameter(line, 5)
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, x := range n.mn.ipsProc {
		if x == ip {
			return true
		}
	}
	return false
}

// MarkIPMNProcessed records the IP of a report whose challenge was answered.
func (n *Node) MarkIPMNProcessed(line string) {
	ip := codec.Parameter(line, 5)
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, x := range n.mn.ipsProc {
		if x == ip {
			return
		}
	}
	if len(n.mn.ipsProc) < maxMNQueue {
		n.mn.ipsProc = append(n.mn.ipsProc, ip)
	}
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

// IsLegitNewNode mirrors nosomasternodes.pas:374-399. FIX(H-01): the funds
// requirement and the "no validations yet" rule apply to EVERY report; in the
// original they lived inside the loop over the existing list, so the first
// report of a block skipped them all.
func (n *Node) IsLegitNewNode(m MNode, block int64) bool {
	if n.Summary.BalanceIndexed(m.Fund) < consensus.GetStackRequired(block+1) || m.Validations != 0 || m.Total != 0 {
		return false
	}
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, e := range n.mn.list {
		if m.IP == e.IP || m.Sign == e.Sign || m.Fund == e.Fund {
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
		Pub:         p(10),
		Sig:         p(11),
		SignPub:     p(12),
		Deleg:       p(13),
	}
	switch {
	case !codec.IsValidIP(m.IP):
		return m, false
	case m.Port < 0 || m.Port > 65535:
	case !crypto.IsValidHashAddress(m.Sign):
	case !crypto.IsValidHashAddress(m.Fund):
	case m.First < 0, m.Last < 0, m.Total < 0, m.Validations < 0:
	case m.Hash != crypto.IDHash(m.IP+codec.IntToStr(int64(m.Port))+m.Sign+m.Fund):
	case crypto.GetAddressFromPublicKey(m.Pub, 0) != m.Fund:
	case m.SignPub == "" && !crypto.VerifyCanonical(m.Pub, m.Sig, "MNREPORT1", mnReportFields(m)...):
	case m.SignPub != "" && (crypto.GetAddressFromPublicKey(m.SignPub, 0) != m.Sign ||
		!crypto.VerifyCanonical(m.Pub, m.Deleg, "MNDELEG1", m.Sign, m.Fund) ||
		!crypto.VerifyCanonical(m.SignPub, m.Sig, "MNREPORT1", mnReportFields(m)...)):
	default:
		return m, true
	}
	return m, false
}

// mnReportFields are the signed fields of a report. FIX(H-01): the original
// report carried no signature at all.
func mnReportFields(m MNode) []string {
	return []string{m.IP, codec.IntToStr(int64(m.Port)), m.Sign, m.Fund, codec.IntToStr(int64(m.First))}
}

// StringFromMN mirrors GetStringFromMN.
func StringFromMN(m MNode) string {
	i := func(v int32) string { return codec.IntToStr(int64(v)) }
	return m.IP + " " + i(m.Port) + " " + m.Sign + " " + m.Fund + " " + i(m.First) + " " +
		i(m.Last) + " " + i(m.Total) + " " + i(m.Validations) + " " + m.Hash + " " + m.Pub + " " + m.Sig +
		deleg(m)
}

func deleg(m MNode) string {
	if m.SignPub == "" {
		return ""
	}
	return " " + m.SignPub + " " + m.Deleg
}

// SignDelegation is made once, offline, with the funds key: it lets the
// sign key report the masternode so the funds key can stay cold.
func SignDelegation(fundsPriv, sign, fund string) string {
	return crypto.SignCanonical(fundsPriv, "MNDELEG1", sign, fund)
}

const delegationFile = "mndelegation.txt"

// SetDelegation stores "fundsPub signature" for the configured sign and funds
// addresses after checking it.
func (n *Node) SetDelegation(fundsPub, sig string) error {
	o := n.Options()
	if crypto.GetAddressFromPublicKey(fundsPub, 0) != o.MNFunds ||
		!crypto.VerifyCanonical(fundsPub, sig, "MNDELEG1", o.MNSign, o.MNFunds) {
		return ErrBadSig
	}
	return os.WriteFile(n.seqFile(delegationFile), []byte(fundsPub+" "+sig), 0o600)
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
	// FIX(H-01): a report is bound to the current block.
	if !ok || int64(m.First) != block || int64(m.Last) != block || !n.IsLegitNewNode(m, block) {
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

// MNReportString mirrors GetMNReportString (nosomasternodes.pas:165-171) and
// signs it with the funds address key (FIX(H-01)). It returns "" when the
// wallet does not hold that key.
func (n *Node) MNReportString(block int64) string {
	o := n.Options()
	w := n.Wallet.At(n.Wallet.IndexOf(o.MNFunds))
	if o.MNFunds == "" {
		return ""
	}
	port, _ := codec.StrToInt(o.MNPort)
	if w.PrivateKey == "" {
		// Cold funds: the sign key reports under a stored delegation.
		raw, err := os.ReadFile(n.seqFile(delegationFile))
		sw := n.Wallet.At(n.Wallet.IndexOf(o.MNSign))
		if err != nil || sw.PrivateKey == "" {
			return ""
		}
		fp, sig := codec.Parameter(string(raw), 0), codec.Parameter(string(raw), 1)
		m := MNode{IP: o.MNIP, Port: port, Sign: o.MNSign, Fund: o.MNFunds, First: int32(block), Last: int32(block),
			Hash: crypto.IDHash(o.MNIP + o.MNPort + o.MNSign + o.MNFunds), Pub: fp, SignPub: sw.PublicKey, Deleg: sig}
		m.Sig = crypto.SignCanonical(sw.PrivateKey, "MNREPORT1", mnReportFields(m)...)
		return StringFromMN(m)
	}
	m := MNode{IP: o.MNIP, Port: port, Sign: o.MNSign, Fund: o.MNFunds, First: int32(block), Last: int32(block),
		Hash: crypto.IDHash(o.MNIP + o.MNPort + o.MNSign + o.MNFunds), Pub: w.PublicKey}
	m.Sig = crypto.SignCanonical(w.PrivateKey, "MNREPORT1", mnReportFields(m)...)
	return StringFromMN(m)
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
	creditChecks(n.mn.list, n.mn.checks)
}

func creditChecks(list []MNode, checks []MNCheck) {
	for _, c := range checks {
		nodes := strings.ReplaceAll(c.ValidNodes, ":", " ")
		seen := map[string]bool{}
		for i := int64(0); ; i++ {
			ip := strings.ReplaceAll(codec.Parameter(nodes, i), ";", " ")
			ip = codec.Parameter(ip, 0)
			if ip == "" {
				break
			}
			// FIX(C-07): a validator counts at most once per masternode.
			if seen[ip] {
				continue
			}
			seen[ip] = true
			for j := range list {
				if list[j].IP == ip {
					list[j].Validations++
					break
				}
			}
		}
	}
}

// paidMNs returns the funds addresses a block built now would pay, without
// consuming any state: the validations are credited on a copy, so a block
// build that fails and is retried sees the same list. Eligible addresses are
// valid, distinct and hold the stake at this height (the rule followers
// check, so an honest builder is never refused).
func (n *Node) paidMNs(block int64) (text string, addrs []string) {
	n.mn.mu.Lock()
	list := append([]MNode(nil), n.mn.list...)
	checks := append([]MNCheck(nil), n.mn.checks...)
	n.mn.mu.Unlock()
	creditChecks(list, checks)
	minV := int32(len(checks)/2 - 1)
	text = codec.IntToStr(block)
	seen := map[string]bool{}
	for _, m := range list {
		if m.Validations < minV {
			continue
		}
		a := codec.Truncate(m.Fund, 32)
		if seen[a] || !MNEligible(n, a, block) {
			continue
		}
		seen[a] = true
		addrs = append(addrs, a)
		text += " " + m.IP + ";" + codec.IntToStr(int64(m.Port)) + ":" + m.Fund + n.MNFile.AgeCount(m.IP, int(m.Port), m.Fund)
	}
	return text, addrs
}

// MNEligible is the consensus rule for a paid masternode address: a regular
// address holding at least the required stake in the summary as of the
// previous block.
func MNEligible(n *Node, addr string, block int64) bool {
	return len(addr) <= 32 && crypto.IsValidHashAddress(addr) && n.Summary.BalanceIndexed(addr) >= consensus.GetStackRequired(block)
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

// validatorAddress returns the sign address registered for a validator IP in
// the ValidatorKeys option ("ip=Naddress,ip=Naddress"), or "".
func (n *Node) validatorAddress(ip string) string {
	for _, kv := range strings.Split(n.Options().ValidatorKeys, ",") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 && p[0] == ip {
			return p[1]
		}
	}
	return ""
}

// IsValidator reports whether ip is a registered masternode verifier.
// FIX(C-07): the original treated every seed IP as a validator
// (nosonetwork.pas:709-713) and never tied a signing key to it.
func (n *Node) IsValidator(ip string) bool { return n.validatorAddress(ip) != "" }

// MNCheckFields are the signed fields of a masternode check.
func MNCheckFields(c MNCheck) []string {
	return []string{codec.IntToStr(int64(c.Block)), c.ValidatorIP, c.SignAddress, c.ValidNodes}
}

// ValidateMNCheck mirrors nosonetwork.pas:716-739. FIX(C-07): the validator
// IP must be registered together with the sign address, the key must belong
// to that address, and the signature covers block, validator and nodes under
// a dedicated domain. All failures reject (the original accepted any key that
// matched its own claimed address).
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
	reg := n.validatorAddress(c.ValidatorIP)
	bad := reg == "" || reg != c.SignAddress || int64(c.Block) != n.MyLastBlock() ||
		crypto.GetAddressFromPublicKey(c.PubKey, 0) != c.SignAddress ||
		!crypto.VerifyCanonical(c.PubKey, c.Signature, "MNCHECK1", MNCheckFields(c)...)
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

// maxMNQueue bounds the received-IP table and the waiting reports (FIX(M-2)):
// at 2 KiB a line, an unbounded queue was 12 MB per slot per ten minutes.
const maxMNQueue = 4096

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
	if len(n.mn.received) >= maxMNQueue {
		return true // FIX(M-2): bounded; the table is cleared every block
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

// AddWaitingMN mirrors AddWaitingMNs. FIX(F-5): a report does not take its
// IP's slot by being queued. It is refused when the IP already answered a
// challenge this block (MNIPReceived) or the same line is already waiting; the
// slot is taken by MarkMNIPReceived after the challenge.
func (n *Node) AddWaitingMN(line string) {
	ip := codec.Parameter(line, 5)
	n.mn.mu.Lock()
	defer n.mn.mu.Unlock()
	for _, x := range n.mn.received {
		if x == ip {
			return
		}
	}
	for _, w := range n.mn.waiting {
		if w == line {
			return
		}
	}
	if len(n.mn.waiting) < maxMNQueue {
		n.mn.waiting = append(n.mn.waiting, line)
	}
}

// MarkMNIPReceived records the IP of a report that answered its challenge.
func (n *Node) MarkMNIPReceived(line string) { n.MNIPReceived(line) }

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

// VerificationLine answers an MNVER challenge. FIX(M-05): the answer is
// signed with the Sign key over the verifier's random nonce, so only a node
// that controls that key (and is synced) can produce it; the original
// returned an unauthenticated text (nosonetwork.pas:522-530).
func (n *Node) VerificationLine(nonce string) string {
	o := n.Options()
	w := n.Wallet.At(n.Wallet.IndexOf(o.MNSign))
	if len(nonce) < 8 || len(nonce) > 64 || w.PrivateKey == "" || n.IsAllSynced() != 0 {
		return "False"
	}
	st := n.SyncTus()
	sig := crypto.SignCanonical(w.PrivateKey, "MNVER1", nonce, st, o.MNFunds)
	return "True " + st + " " + o.MNFunds + " " + o.MNSign + " " + w.PublicKey + " " + sig
}

// CheckVerificationLine validates an MNVER answer for the masternode m.
func CheckVerificationLine(line, nonce, synctus string, m MNode) bool {
	p := func(i int64) string { return codec.Parameter(line, i) }
	if p(0) != "True" || p(1) != synctus || p(2) != m.Fund || p(3) != m.Sign {
		return false
	}
	return crypto.GetAddressFromPublicKey(p(4), 0) == m.Sign &&
		crypto.VerifyCanonical(p(4), p(5), "MNVER1", nonce, synctus, m.Fund)
}
