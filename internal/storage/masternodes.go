package storage

import (
	"os"
	"strings"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
)

// MNEntry is one parsed element of the masternodes file (TMNsData).
type MNEntry struct {
	IPAndPort string
	Address   string
	Age       int
}

// MNFile is masternodes.txt: one line "Block ip;port:fund:age ip;port:fund:age"
// terminated by CR LF (nosomasternodes.pas:812-828).
type MNFile struct {
	mu   sync.Mutex
	path string
	text string
	arr  []MNEntry
}

// OpenMNFile mirrors SetMasternodesFilename: create when missing, then load.
func OpenMNFile(path string) *MNFile {
	m := &MNFile{path: path}
	if !Exists(path) {
		_ = os.WriteFile(path, nil, 0o644)
	}
	m.Load()
	return m
}

// Path returns the file path.
func (m *MNFile) Path() string { return m.path }

// Load mirrors LoadMNsFile: the first line only (CR LF stripped).
func (m *MNFile) Load() string {
	b, _ := os.ReadFile(m.path)
	line := string(b)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSuffix(line, "\r")
	m.set(line)
	return line
}

// Save mirrors SaveMNsFile: text + CR LF.
func (m *MNFile) Save(text string) {
	_ = writeFileAtomic(m.path, []byte(text+"\r\n"))
	m.set(text)
}

func (m *MNFile) set(text string) {
	m.mu.Lock()
	m.text = text
	m.arr = fillMNsArray(text)
	m.mu.Unlock()
}

// Text returns MN_FileText.
func (m *MNFile) Text() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.text
}

// Hash mirrors GetMNsHash: MD5 of the file as it is on disk.
func (m *MNFile) Hash() string { return crypto.IDHashFile(m.path) }

// Entries returns ArrayMNsData (sorted by descending age, stable).
func (m *MNFile) Entries() []MNEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MNEntry(nil), m.arr...)
}

// fillMNsArray mirrors FillMNsArray (nosomasternodes.pas:848-898): the
// file text is parsed from parameter 1, each "ip;port:fund:age" element is
// split, and the elements are ordered by descending age with an insertion
// that places an element before the first strictly younger one.
func fillMNsArray(text string) []MNEntry {
	var tmp []MNEntry
	for i := int64(1); ; i++ {
		d := codec.Parameter(text, i)
		if d == "" {
			break
		}
		d = strings.ReplaceAll(d, ":", " ")
		tmp = append(tmp, MNEntry{codec.Parameter(d, 0), codec.Parameter(d, 1),
			int(codec.StrToIntDef(codec.Parameter(d, 2), 1))})
	}
	var out []MNEntry
	for _, t := range tmp {
		added := false
		for j := range out {
			if t.Age > out[j].Age {
				out = append(out, MNEntry{})
				copy(out[j+1:], out[j:])
				out[j] = t
				added = true
				break
			}
		}
		if !added {
			out = append(out, t)
		}
	}
	return out
}

// VerificatorsText mirrors GetVerificatorsText (nosomasternodes.pas:900-912):
// the "ip;port:" list of the oldest (len/10)+3 masternodes. COMPAT: fewer
// than 3 entries gives "".
func (m *MNFile) VerificatorsText() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.arr) < 3 {
		return ""
	}
	n := len(m.arr)/10 + 3
	var sb strings.Builder
	for i := 0; i < n && i < len(m.arr); i++ {
		sb.WriteString(m.arr[i].IPAndPort + ":")
	}
	return sb.String()
}

// AgeCount mirrors GetMNAgeCount: ":"+(age+1) for a known ip/port/fund.
func (m *MNFile) AgeCount(ip string, port int, fund string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := ip + ";" + codec.IntToStr(int64(port))
	age := 0
	for _, e := range m.arr {
		if e.IPAndPort == key && e.Address == fund {
			age = e.Age
			break
		}
	}
	return ":" + codec.IntToStr(int64(age+1))
}
