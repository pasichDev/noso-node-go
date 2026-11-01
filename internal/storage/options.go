package storage

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// Options is the content of advopt.txt (mpdisk.pas:232-386) together with
// the runtime defaults declared in masterpaskalform.pas:621-650.
type Options struct {
	// partial is set when the last Load stopped before the end of the file:
	// Save then refuses, so the unread settings are not overwritten by blanks.
	partial      bool
	HideEmpty    bool
	MultiSend    bool
	Language     string
	NoGUI        bool
	LastPoUpdate string
	CloseStart   bool
	SendReport   bool
	BlocksDB     bool
	PRestart     int64
	SkipBlocks   bool
	FormState    [5]int64 // top left width height state
	AutoServer   bool
	AutoUpdate   bool
	FullNode     bool
	MNIP         string
	MNPort       string
	MNFunds      string
	MNSign       string
	MNAutoIP     bool
	RPCPort      int
	RPCPass      string
	RPCFilter    bool
	RPCWhitelist string
	RPCAuto      bool
	RPCSaveNew   bool
	RPCBanned    string
	MaxPeers     int
	PosWarning   int64

	// Security settings added by this port. None has a default key: an empty
	// key means "nobody is trusted for that purpose".
	AdminKey      string // public key (Base64) allowed to sign directives and GVT transfers
	ConfigKey     string // public key allowed to sign the network configuration
	ValidatorKeys string // "ip=Naddress,ip=Naddress": masternode verifiers and their sign addresses
	SeedKeys      string // "ip=publickey,...": keys of seed nodes that sign status replies
	ReleaseKey    string // public key that signs the default seed list
	BuildBlocks   bool   // this node proposes blocks (see docs/compatibility.md, M-10)
	RPCToken      string // read scope bearer token
	RPCSpendToken string // spend scope bearer token
	RPCBind       string // listen address of the RPC server, loopback by default
	RPCExposeKeys bool   // include private keys in getnewaddressfull answers
}

// DefaultOptions returns the Pascal variable initialisers.
func DefaultOptions(release string) Options {
	return Options{
		Language: "en", LastPoUpdate: release, CloseStart: true, AutoUpdate: true,
		FullNode: true, MNPort: "8080", RPCPort: 8078, RPCPass: "", RPCBind: "127.0.0.1",
		RPCFilter: true, RPCWhitelist: "127.0.0.1,localhost", MaxPeers: 50, PosWarning: 7,
		FormState: [5]int64{0, 0, 400, 560, 2},
	}
}

func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// strToBool mirrors SysUtils.StrToBool; invalid text leaves the previous
// value (Pascal would raise and abort loading the rest of the file, see
// LoadADV's try/except).
func strToBool(s string) (bool, bool) { return codec.TryStrToBool(s) }

// Save writes advopt.txt exactly as CreateADV does.
//
// FIX(re2 #8, #9): the file is replaced atomically with mode 0600 (an existing
// 0644 advopt.txt from the Pascal node is tightened), and nothing is written
// after a Load that did not read the whole file.
func (o *Options) Save(path string) error {
	if o.partial {
		return errors.New("advopt: the file was only partly read; not overwriting it (fix or remove the offending line)")
	}
	var sb strings.Builder
	w := func(s string) { sb.WriteString(s + "\n") }
	w("---NosoNode config file.---")
	w("")
	w("---Wallet related.---")
	w("//Hide empty addresses")
	w("HideEmpty " + boolStr(o.HideEmpty))
	w("//Use all addresses to send funds")
	w("MultiSend " + boolStr(o.MultiSend))
	w("//Po files language code")
	w("Language " + o.Language)
	w("//No GUI refresh")
	w("NoGUI " + boolStr(o.NoGUI))
	w("//Po files last update")
	w("PoUpdate " + o.LastPoUpdate)
	w("//Close the launch form automatically")
	w("Closestart " + boolStr(o.CloseStart))
	w("//Send anonymous report to developers")
	w("SendReport " + boolStr(o.SendReport))
	w("//Keep a blocks database")
	w("BlocksDB " + boolStr(o.BlocksDB))
	w("//Restart periodically the node")
	w("PRestart " + codec.IntToStr(o.PRestart))
	w("//Skip new blocks creation")
	w("SkipBlocks " + boolStr(o.SkipBlocks))
	w("//Mainform coordinates. Do not manually change this values")
	w("FormState " + codec.IntToStr(o.FormState[0]) + " " + codec.IntToStr(o.FormState[1]) + " " +
		codec.IntToStr(o.FormState[2]) + " " + codec.IntToStr(o.FormState[3]) + " " + codec.IntToStr(o.FormState[4]))
	w("")
	w("---Masternode---")
	w("//Enable node server at start")
	w("Autoserver " + boolStr(o.AutoServer))
	w("//Run autoupdate directives")
	w("Autoupdate " + boolStr(o.AutoUpdate))
	w("//Download the complete blockchain")
	w("WO_FullNode " + boolStr(o.FullNode))
	w("//Masternode static IP")
	w("MNIP " + o.MNIP)
	w("//Masternode port")
	w("MNPort " + o.MNPort)
	w("//Masternode funds address")
	w("MNFunds " + o.MNFunds)
	w("//Masternode sign address")
	w("MNSign " + o.MNSign)
	w("//Use automatic IP detection for masternode")
	w("MNAutoIp " + boolStr(o.MNAutoIP))
	w("")
	w("---RPC server---")
	w("//RPC server port")
	w("RPCPort " + codec.IntToStr(int64(o.RPCPort)))
	w("//RPC server password")
	w("RPCPass " + o.RPCPass)
	w("//RPC IP filter active/inactive")
	w("RPCFilter " + boolStr(o.RPCFilter))
	w("//RPC whitelisted IPs")
	w("RPCWhiteList " + o.RPCWhitelist)
	w("//Enable RPC server at start")
	w("RPCAuto " + boolStr(o.RPCAuto))
	w("//Save addresses keys created on a BAK folder")
	w("RPCSaveNew " + boolStr(o.RPCSaveNew))
	w("//Banned methods for RPC requests")
	w("RPCBanned " + o.RPCBanned)
	w("")
	w("---Security (added by this port)---")
	w("AdminKey " + o.AdminKey)
	w("ConfigKey " + o.ConfigKey)
	w("ValidatorKeys " + o.ValidatorKeys)
	w("SeedKeys " + o.SeedKeys)
	w("ReleaseKey " + o.ReleaseKey)
	w("BuildBlocks " + boolStr(o.BuildBlocks))
	w("RPCToken " + o.RPCToken)
	w("RPCSpendToken " + o.RPCSpendToken)
	w("RPCBind " + o.RPCBind)
	w("RPCExposeKeys " + boolStr(o.RPCExposeKeys))
	w("")
	w("---Deprecated. To be removed.---")
	w("MaxPeers " + codec.IntToStr(int64(o.MaxPeers)))
	w("PosWarning " + codec.IntToStr(o.PosWarning))
	return writeFileAtomic(path, []byte(sb.String())) // FIX(H-10): holds tokens, 0600
}

// Load mirrors LoadADV: lines are matched on their first blank-separated
// word (case sensitive). COMPAT BREAK (re2 #9): the original stops at an
// invalid boolean, which here would leave every later setting (AdminKey,
// tokens) at its default and blank it on the next Save; this port skips the
// bad line, reads the rest and returns an error naming the first bad line.
// A read error (for instance a line over 1 MiB) stops the load and makes Save
// refuse. A Pascal-era file with a loose mode is tightened to 0600.
func (o *Options) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(path, 0o600)
	}
	o.partial = false
	var firstBad error
	lineNo := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSuffix(sc.Text(), "\r")
		p := func(n int64) string { return codec.Parameter(line, n) }
		bl := func(dst *bool) bool {
			v, ok := strToBool(p(1))
			if !ok {
				return false
			}
			*dst = v
			return true
		}
		ok := true
		switch p(0) {
		case "RPCPort":
			o.RPCPort = int(codec.StrToIntDef(p(1), int64(o.RPCPort)))
		case "RPCPass":
			o.RPCPass = p(1)
		case "MaxPeers":
			o.MaxPeers = int(codec.StrToIntDef(p(1), int64(o.MaxPeers)))
		case "PosWarning":
			o.PosWarning = codec.StrToIntDef(p(1), o.PosWarning)
		case "SendReport":
			ok = bl(&o.SendReport)
		case "BlocksDB":
			ok = bl(&o.BlocksDB)
		case "PRestart":
			o.PRestart = codec.StrToIntDef(p(1), 0)
		case "SkipBlocks":
			ok = bl(&o.SkipBlocks)
		case "MultiSend":
			ok = bl(&o.MultiSend)
		case "HideEmpty":
			ok = bl(&o.HideEmpty)
		case "RPCFilter":
			ok = bl(&o.RPCFilter)
		case "RPCWhiteList":
			o.RPCWhitelist = p(1)
		case "RPCBanned":
			o.RPCBanned = p(1)
		case "RPCAuto":
			ok = bl(&o.RPCAuto)
		case "RPCSaveNew":
			ok = bl(&o.RPCSaveNew)
		case "Language":
			o.Language = p(1)
		case "Autoserver":
			ok = bl(&o.AutoServer)
		case "PoUpdate":
			o.LastPoUpdate = p(1)
		case "Closestart":
			ok = bl(&o.CloseStart)
		case "Autoupdate":
			ok = bl(&o.AutoUpdate)
		case "NoGUI":
			ok = bl(&o.NoGUI)
		case "FormState":
			o.FormState = [5]int64{codec.StrToIntDef(p(1), 0), codec.StrToIntDef(p(2), 0),
				codec.StrToIntDef(p(3), 400), codec.StrToIntDef(p(4), 560), codec.StrToIntDef(p(5), 2)}
		case "MNIP":
			o.MNIP = p(1)
		case "MNPort":
			o.MNPort = p(1)
		case "MNFunds":
			o.MNFunds = p(1)
		case "MNSign":
			o.MNSign = p(1)
		case "AdminKey":
			o.AdminKey = p(1)
		case "ConfigKey":
			o.ConfigKey = p(1)
		case "ValidatorKeys":
			o.ValidatorKeys = p(1)
		case "SeedKeys":
			o.SeedKeys = p(1)
		case "ReleaseKey":
			o.ReleaseKey = p(1)
		case "BuildBlocks":
			ok = bl(&o.BuildBlocks)
		case "RPCToken":
			o.RPCToken = p(1)
		case "RPCSpendToken":
			o.RPCSpendToken = p(1)
		case "RPCBind":
			o.RPCBind = p(1)
		case "RPCExposeKeys":
			ok = bl(&o.RPCExposeKeys)
		case "MNAutoIp":
			ok = bl(&o.MNAutoIP)
		case "WO_FullNode":
			ok = bl(&o.FullNode)
		}
		if !ok && firstBad == nil {
			firstBad = fmt.Errorf("advopt: line %d: invalid boolean", lineNo)
		}
	}
	if err := sc.Err(); err != nil {
		o.partial = true
		return fmt.Errorf("advopt: stopped reading after line %d: %w", lineNo, err)
	}
	return firstBad
}
