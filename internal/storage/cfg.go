package storage

import (
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// DefaultNosoCFG is nosonosocfg.pas:41-47. Fields, separated by blanks:
// 0 mainnet mode, 1 seed nodes, 2 NTP servers, 3 and 4 deprecated, 5 frozen
// (locked) addresses.
const DefaultNosoCFG = "NORMAL " +
	"204.10.194.22;8080:204.10.194.29;8080:204.10.194.32;8080:204.10.194.36;8080:204.10.194.33;8080:38.242.252.153;8080:157.173.99.119;8080:38.242.252.234;8080:4.233.61.8;8080: " +
	"ts2.aco.net:hora.roa.es:time.esa.int:time.stdtime.gov.tw:stratum-1.sjc02.svwh.net:ntp1.sp.se:1.de.pool.ntp.org:ntps1.pads.ufrj.br:utcnist2.colorado.edu:tick.usask.ca:ntp1.st.keio.ac.jp: " +
	"null: " +
	"null: " +
	"NpryectdevepmentfundsGE:"

// ErrCFGIndex is returned where Pascal would raise a range error.
var ErrCFGIndex = errors.New("nosocfg: field index out of range")

// CFG is nosocfg.psk, a one line text file split by blanks into fields
// (nosonosocfg.pas).
type CFG struct {
	mu   sync.Mutex
	path string
	data string
	hash string
	// LastRequest mirrors LasTimeCFGRequest.
	LastRequest int64
	// Now supplies the UTC clock for LastRequest.
	Now func() int64
	// FetchSeeds optionally downloads the default seed list when the file is
	// created (nosonosocfg.pas:81). nil disables the download.
	FetchSeeds func() string
}

// OpenCFG mirrors SetCFGFilename (nosonosocfg.pas:71-94).
func OpenCFG(path string, now func() int64, fetch func() string) *CFG {
	c := &CFG{path: path, Now: now, FetchSeeds: fetch}
	if !Exists(path) {
		c.Save(DefaultNosoCFG)
		c.Reload()
		if fetch != nil {
			if seeds := fetch(); seeds != "" {
				_ = c.SetData(seeds, 1)
			}
		}
	}
	c.Reload()
	c.setHash()
	return c
}

func (c *CFG) setHash() {
	c.hash = crypto.IDHash(c.data)
}

// Hash returns MyCFGHash.
func (c *CFG) Hash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hash
}

// Save writes the text to disk and makes it current (SaveCFGToFile).
func (c *CFG) Save(content string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := writeFileAtomic(c.path, []byte(content))
	c.data = content
	c.setHash()
	return err == nil
}

// Reload mirrors GetCFGFromFile.
func (c *CFG) Reload() {
	b, _ := os.ReadFile(c.path)
	c.mu.Lock()
	c.data = string(b)
	c.setHash()
	c.mu.Unlock()
}

// SetDataStr mirrors SetCFGDataStr (memory only).
func (c *CFG) SetDataStr(s string) {
	c.mu.Lock()
	c.data = s
	c.setHash()
	c.mu.Unlock()
}

// DataStr mirrors GetCFGDataStr(-1); Param mirrors GetCFGDataStr(n).
func (c *CFG) DataStr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data
}

// Param returns blank separated field n.
func (c *CFG) Param(n int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return codec.Parameter(c.data, int64(n))
}

// fields reproduces the loader loop shared by Add/Remove/Set: it stops at
// the first EMPTY field (nosonosocfg.pas:148-153).
func (c *CFG) fields() []string {
	cur := c.DataStr()
	var arr []string
	for i := int64(0); ; i++ {
		p := codec.Parameter(cur, i)
		if p != "" {
			arr = append(arr, p)
		}
		if p == "" {
			break
		}
	}
	return arr
}

func (c *CFG) touch() {
	if c.Now != nil {
		c.LastRequest = c.Now() + 5
	}
}

// Add mirrors AddCFGData (nosonosocfg.pas:135-168).
func (c *CFG) Add(add string, idx int) error {
	if idx < 0 {
		return ErrCFGIndex
	}
	if add == "" || add[len(add)-1] != ':' {
		add += ":"
	}
	arr := c.fields()
	for idx+1 > len(arr) {
		arr = append(arr, "")
	}
	arr[idx] += add
	final := ""
	for _, a := range arr {
		final += " " + a
	}
	if final != "" && final[0] == ' ' {
		final = final[1:]
	}
	c.Save(final)
	c.touch()
	return nil
}

// Remove mirrors RemoveCFGData (nosonosocfg.pas:170-200).
func (c *CFG) Remove(rem string, idx int) error {
	if len(rem) > 0 && rem[len(rem)-1] != ':' {
		rem += ":"
	}
	arr := c.fields()
	if idx < 0 || idx >= len(arr) {
		return ErrCFGIndex
	}
	arr[idx] = replaceFold(arr[idx], rem)
	final := ""
	for _, a := range arr {
		final += " " + a
	}
	final = codec.Trim(final)
	c.touch()
	c.Save(final)
	return nil
}

// SetData mirrors SetCFGData (nosonosocfg.pas:202-230).
func (c *CFG) SetData(set string, idx int) error {
	if len(set) > 0 && set[len(set)-1] != ':' && idx > 0 {
		set += ":"
	}
	if idx == 0 && set == "" {
		return nil
	}
	arr := c.fields()
	if idx < 0 || idx >= len(arr) {
		return ErrCFGIndex
	}
	arr[idx] = set
	final := ""
	for _, a := range arr {
		final += " " + a
	}
	final = codec.Trim(final)
	c.touch()
	c.Save(final)
	return nil
}

// Restore mirrors RestoreCFGData.
func (c *CFG) Restore() {
	c.touch()
	c.Save(DefaultNosoCFG)
}

// Clear mirrors ClearCFGData.
func (c *CFG) Clear(index string) {
	i := codec.StrToIntDef(index, -1)
	if i <= 0 {
		return
	}
	_ = c.SetData("null:", int(i))
}

// IsSeedNode mirrors nosonosocfg.pas:252-259.
func (c *CFG) IsSeedNode(ip string) bool {
	return strings.Contains(":"+c.Param(1), ":"+ip+";")
}

// replaceFold is StringReplace(s, old, "", [rfReplaceAll, rfIgnoreCase]).
func replaceFold(s, old string) string {
	if old == "" {
		return s
	}
	ls, lo := strings.ToLower(s), strings.ToLower(old)
	var sb strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(ls[i:], lo) {
			i += len(old)
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}
