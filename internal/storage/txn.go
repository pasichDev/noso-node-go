package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Multi-file atomic commit (journal).
//
// A block and the state it produces (summary, headers, GVTs, PSOs, ...) live
// in separate files; a crash between two plain writes leaves them disagreeing.
// Txn makes a set of whole-file replacements all-or-nothing:
//
//	t := storage.NewTxn(layout.Root)
//	t.Add(layout.BlockFile(n), blockBytes)
//	t.Add(layout.Headers, headersBytes)
//	t.Add(layout.Summary, summaryBytes)
//	err := t.Commit()
//
// Commit stages every file as <path>.new (written and fsynced), then writes
// the manifest root/commit.journal atomically. The manifest is the commit
// point: from the moment it is durable the transaction WILL happen, before it
// nothing happened. Then the staged files are renamed over their targets and
// the manifest is removed. RecoverTxn (run by LockDataDir on every start)
// rolls a durable manifest forward and deletes the debris of a transaction
// that never reached its commit point. After a crash the files are therefore
// either all old or all new.
//
// Limits: whole-file replacement only (the summary is a large file written in
// place by UpdateChanges; using Txn for it means writing the full image, or
// keeping the in-place update and journaling the small files around it);
// one transaction at a time per data directory (the caller serialises, like
// the node already does for block commits); paths must be inside root. If
// Commit returns an error wrapping ErrTxnPending the journal is durable but
// applying it failed: stop writing and restart, recovery completes it.

const (
	journalName  = "commit.journal"
	journalMagic = "NOSOTXN1"
)

// ErrTxnPending is wrapped by Commit when the transaction passed its commit
// point but could not be applied; RecoverTxn finishes it on the next start.
var ErrTxnPending = errors.New("storage: transaction committed to the journal but not fully applied; restart to complete it")

// Txn collects whole-file replacements for one atomic commit.
type Txn struct {
	root string
	ops  []txnOp
}

type txnOp struct {
	path string
	data []byte
}

// NewTxn starts a transaction for the data directory root.
func NewTxn(root string) *Txn { return &Txn{root: root} }

// Add queues path to be replaced with data. A path added twice keeps the last data.
func (t *Txn) Add(path string, data []byte) {
	for i := range t.ops {
		if t.ops[i].path == path {
			t.ops[i].data = data
			return
		}
	}
	t.ops = append(t.ops, txnOp{path, data})
}

func (t *Txn) rel(path string) (string, error) {
	r, err := filepath.Rel(t.root, path)
	if err != nil || r == "." || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", fmt.Errorf("storage: %s is outside %s", path, t.root)
	}
	if strings.ContainsAny(r, "\n\r") || strings.HasSuffix(r, ".new") {
		return "", fmt.Errorf("storage: unsupported journal path %q", r)
	}
	return filepath.ToSlash(r), nil
}

// Commit applies the transaction atomically (see the package comment above).
func (t *Txn) Commit() error {
	if len(t.ops) == 0 {
		return nil
	}
	var body bytes.Buffer
	body.WriteString(journalMagic + "\n")
	dirs := map[string]bool{}
	for _, op := range t.ops {
		r, err := t.rel(op.path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(op.data)
		body.WriteString(hex.EncodeToString(sum[:]) + " " + r + "\n")
		dirs[filepath.Dir(op.path)] = true
	}
	staged := 0
	cleanup := func() {
		for _, op := range t.ops[:staged] {
			_ = os.Remove(op.path + ".new")
		}
	}
	for _, op := range t.ops {
		if err := writeSynced(op.path+".new", op.data); err != nil {
			_ = os.Remove(op.path + ".new")
			cleanup()
			return err
		}
		staged++
	}
	for d := range dirs {
		if err := syncDir(d); err != nil {
			cleanup()
			return err
		}
	}
	sum := sha256.Sum256(body.Bytes())
	body.WriteString("END " + hex.EncodeToString(sum[:]) + "\n")
	jp := filepath.Join(t.root, journalName)
	if err := writeFileAtomic(jp, body.Bytes()); err != nil {
		_ = os.Remove(jp)
		cleanup()
		return err
	}
	// commit point passed
	if err := applyJournal(t.root, body.Bytes()); err != nil {
		return fmt.Errorf("%w: %v", ErrTxnPending, err)
	}
	return nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	_, werr := f.Write(data)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

type journalEntry struct {
	sum  string
	path string // absolute
}

// parseJournal returns the entries of a complete, checksummed manifest.
func parseJournal(root string, raw []byte) ([]journalEntry, bool) {
	i := bytes.LastIndex(raw, []byte("END "))
	if i < 0 || !bytes.HasSuffix(raw, []byte("\n")) {
		return nil, false
	}
	body, tail := raw[:i], strings.TrimSuffix(string(raw[i+4:]), "\n")
	sum := sha256.Sum256(body)
	if tail != hex.EncodeToString(sum[:]) {
		return nil, false
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) < 2 || lines[0] != journalMagic {
		return nil, false
	}
	var out []journalEntry
	for _, ln := range lines[1:] {
		p := strings.SplitN(ln, " ", 2)
		if len(p) != 2 || len(p[0]) != 64 || p[1] == "" {
			return nil, false
		}
		rel := filepath.FromSlash(p[1])
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, false
		}
		out = append(out, journalEntry{p[0], filepath.Join(root, rel)})
	}
	return out, true
}

func fileSum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// applyJournal renames every staged file over its target (idempotent) and
// removes the manifest.
func applyJournal(root string, raw []byte) error {
	ents, ok := parseJournal(root, raw)
	if !ok {
		return errors.New("storage: journal unreadable")
	}
	dirs := map[string]bool{root: true}
	for _, e := range ents {
		staged := e.path + ".new"
		if got, err := fileSum(staged); err == nil {
			if got != e.sum {
				return fmt.Errorf("storage: staged file %s does not match the journal", staged)
			}
			if err := os.Rename(staged, e.path); err != nil {
				return err
			}
		} else if errors.Is(err, fs.ErrNotExist) {
			if got, terr := fileSum(e.path); terr != nil || got != e.sum {
				return fmt.Errorf("storage: %s is neither staged nor in its committed state", e.path)
			}
		} else {
			return err
		}
		dirs[filepath.Dir(e.path)] = true
	}
	for d := range dirs {
		if err := syncDir(d); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(root, journalName)); err != nil {
		return err
	}
	return syncDir(root)
}

// RecoverTxn finishes or discards what a crash left of Txn.Commit. It reports
// whether a committed transaction was rolled forward. Call it with the data
// directory locked (LockDataDir does).
func RecoverTxn(root string) (rolledForward bool, err error) {
	jp := filepath.Join(root, journalName)
	raw, rerr := os.ReadFile(jp)
	if rerr == nil {
		if _, ok := parseJournal(root, raw); ok {
			if err := applyJournal(root, raw); err != nil {
				return false, err
			}
			return true, nil
		}
		_ = os.Remove(jp) // torn manifest: the commit point was never reached
	} else if !errors.Is(rerr, fs.ErrNotExist) {
		return false, rerr
	}
	return false, nil
}

// sweepStrays removes the debris of interrupted writes below root: *.new
// (staged, never committed) and *.tmp (atomic write interrupted). A wallet
// temporary holds clear-text or sealed keys and is overwritten before removal.
func sweepStrays(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".new"):
			_ = os.Remove(p)
		case strings.HasSuffix(p, ".tmp"):
			if strings.Contains(filepath.Base(p), "wallet") {
				_ = shred(p)
			} else {
				_ = os.Remove(p)
			}
		}
		return nil
	})
}

// RecoverDataDir rolls a committed journal forward and removes interrupted
// write debris. LockDataDir calls it after taking the lock.
func RecoverDataDir(root string) error {
	if _, err := RecoverTxn(root); err != nil {
		return err
	}
	sweepStrays(root)
	return nil
}

func sha256sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
