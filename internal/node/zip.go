package node

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// ZipSummary mirrors ZipSumary (nosounit.pas:145-169): sumary.zip holds the
// summary under the entry name "data/sumary.psk".
func (n *Node) ZipSummary() error {
	raw, err := n.Summary.Bytes()
	if err != nil {
		return err
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create("data/sumary.psk")
	if err != nil {
		return err
	}
	_, _ = w.Write(raw)
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(n.Lay.SummaryZip, b.Bytes(), 0o644)
}

// ZipBlocks mirrors CreateZipBlockfile (mpprotocol.pas:639-674): blocks
// first..min(first+100,last) zipped under flat entry names "N.blk" (FIX(C-02):
// the original used the path "NOSODATA/BLOCKS/N.blk").
func (n *Node) ZipBlocks(first int64) ([]byte, error) {
	last := first + 100
	if last > n.MyLastBlock() {
		last = n.MyLastBlock()
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := first; i <= last; i++ {
		raw, err := os.ReadFile(n.Lay.BlockFile(i))
		if err != nil {
			continue
		}
		w, err := zw.Create(codec.IntToStr(i) + ".blk")
		if err != nil {
			return nil, err
		}
		_, _ = w.Write(raw)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Limits for a received block archive. FIX(C-02, H-11).
const (
	maxZipEntries   = 128
	maxZipEntrySize = 8 << 20
	maxZipTotal     = 64 << 20
)

var blockEntryName = regexp.MustCompile(`^[0-9]{1,10}\.blk$`)

// StageBlocks decodes a received archive in memory and hands the blocks to
// the chain rules (acceptRunLocked): they are validated, applied to the state
// one by one and stored when they extend our chain or form a heavier branch.
// Nothing is extracted to disk by the archive itself. FIX(C-02, C-03): the original
// unzipped the peer's archive over the node directory with the paths chosen
// by the peer (masterpaskalform.pas:2442-2469, nosogeneral.pas:565-584).
// Only flat entries named <number>.blk are read; links, directories, parent
// references and over-size entries are rejected. It returns the number of
// blocks stored.
func (n *Node) StageBlocks(data []byte) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, err
	}
	if len(zr.File) > maxZipEntries {
		return 0, errors.New("archive has too many entries")
	}
	byNum := map[int64][]byte{}
	var total uint64
	for _, f := range zr.File {
		if !blockEntryName.MatchString(f.Name) || f.Mode()&os.ModeSymlink != 0 || f.FileInfo().IsDir() {
			return 0, errors.New("archive entry not allowed: " + f.Name)
		}
		total += f.UncompressedSize64
		if f.UncompressedSize64 > maxZipEntrySize || total > maxZipTotal {
			return 0, errors.New("archive too large")
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxZipEntrySize+1))
		_ = rc.Close() // read only
		if err != nil || len(raw) > maxZipEntrySize {
			return 0, errors.New("bad archive entry")
		}
		byNum[codec.StrToInt64Def(f.Name[:len(f.Name)-4], -1)] = raw
	}
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.acceptRunLocked(byNum)
}
