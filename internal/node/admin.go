package node

import (
	"errors"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
)

// Errors returned for rejected signed administrative data.
var (
	ErrNoKey     = errors.New("no key configured for this purpose")
	ErrBadSig    = errors.New("signature does not verify")
	ErrReplay    = errors.New("sequence number not newer than the last accepted one")
	ErrExpired   = errors.New("directive expired or too far in the future")
	ErrBadFormat = errors.New("malformed content")
)

// maxDirectiveWindow is how many blocks ahead a directive may expire.
const maxDirectiveWindow = 1008

func (n *Node) seqFile(name string) string { return n.Lay.Root + "/" + name }

func (n *Node) readSeq(name string) int64 {
	b, err := os.ReadFile(n.seqFile(name))
	if err != nil {
		return 0
	}
	return codec.StrToInt64Def(codec.Trim(string(b)), 0)
}

func (n *Node) writeSeq(name string, v int64) error {
	return storage.WriteFileAtomic(n.seqFile(name), []byte(codec.IntToStr(v)))
}

// CFGFields are the signed fields of a configuration. FIX(C-01): the
// original accepted any text whose MD5 started with the voted 5 hex
// characters (mpprotocol.pas:1064-1080).
func CFGFields(seq int64, content string) []string { return []string{codec.IntToStr(seq), content} }

// SignedConfig is a configuration text with its signature.
type SignedConfig struct {
	Seq     int64
	Content string
	Sig     string
}

// AcceptConfig installs a configuration signed by the ConfigKey. The
// sequence number must be higher than the last accepted one (FIX(C-01),
// H-02 style replay protection). Without a configured key nothing is
// accepted (FIX(H-03): no embedded trust anchor).
func (n *Node) AcceptConfig(sc SignedConfig) error {
	key := n.Options().ConfigKey
	if key == "" {
		return ErrNoKey
	}
	if strings.ContainsAny(sc.Content, "\r\n") || len(sc.Content) > 16<<10 || sc.Content == "" {
		return ErrBadFormat
	}
	if !crypto.VerifyCanonical(key, sc.Sig, "CFG1", CFGFields(sc.Seq, sc.Content)...) {
		return ErrBadSig
	}
	if sc.Seq <= n.readSeq("cfg.seq") {
		return ErrReplay
	}
	if err := n.writeSeq("cfg.seq", sc.Seq); err != nil {
		return err
	}
	n.CFG.Save(sc.Content)
	return os.WriteFile(n.seqFile("nosocfg.sig"), []byte(codec.IntToStr(sc.Seq)+" "+sc.Sig), 0o600)
}

// StoredConfig returns the signed configuration we currently hold, if the
// local file still matches the signature.
func (n *Node) StoredConfig() (SignedConfig, bool) {
	b, err := os.ReadFile(n.seqFile("nosocfg.sig"))
	if err != nil {
		return SignedConfig{}, false
	}
	seq := codec.StrToInt64Def(codec.Parameter(string(b), 0), 0)
	sc := SignedConfig{Seq: seq, Content: n.CFG.DataStr(), Sig: codec.Parameter(string(b), 1)}
	key := n.Options().ConfigKey
	if key == "" || !crypto.VerifyCanonical(key, sc.Sig, "CFG1", CFGFields(sc.Seq, sc.Content)...) {
		return SignedConfig{}, false
	}
	return sc, true
}

// DirectiveFields are the signed fields of an admin directive. FIX(H-02):
// the original signed only time+text, so a directive stayed valid forever
// and could be replayed (mpprotocol.pas:987-1062); a sequence number, an
// expiry height and a domain tag are now part of the signature.
func DirectiveFields(seq, expiry int64, text string) []string {
	return []string{codec.IntToStr(seq), codec.IntToStr(expiry), text}
}

// AcceptDirective validates a directive and applies it when it is a
// configuration directive. Directives that would update or restart the
// program, or move funds, do not exist in this implementation (FIX(C-08,
// H-03)). It returns the directive text on success.
func (n *Node) AcceptDirective(seq, expiry int64, text, sig string) (string, error) {
	key := n.Options().AdminKey
	if key == "" {
		return "", ErrNoKey
	}
	if !crypto.VerifyCanonical(key, sig, "DIRECTIVE1", DirectiveFields(seq, expiry, text)...) {
		return "", ErrBadSig
	}
	last := n.MyLastBlock()
	if expiry < last || expiry > last+maxDirectiveWindow {
		return "", ErrExpired
	}
	if seq <= n.readSeq("directive.seq") {
		return "", ErrReplay
	}
	if err := n.writeSeq("directive.seq", seq); err != nil {
		return "", err
	}
	n.applyDirective(text)
	return text, nil
}

func (n *Node) applyDirective(text string) {
	cmd, param := strings.ToUpper(codec.Parameter(text, 0)), codec.Parameter(text, 1)
	switch cmd {
	case "SETMODE":
		_ = n.CFG.SetData(param, 0)
	case "ADDNODE":
		_ = n.CFG.Add(param, 1)
	case "DELNODE":
		_ = n.CFG.Remove(param, 1)
	case "ADDNTP":
		_ = n.CFG.Add(param, 2)
	case "DELNTP":
		_ = n.CFG.Remove(param, 2)
	case "ADDLOCKED":
		_ = n.CFG.Add(param, 5)
	case "DELLOCKED":
		_ = n.CFG.Remove(param, 5)
	case "CLEARCFG":
		n.CFG.Clear(param)
	case "RESTORECFG":
		n.CFG.Restore()
	}
	// UPDATE, RESTART, ADDNOSOPAY and DELNOSOPAY are intentionally ignored.
}
