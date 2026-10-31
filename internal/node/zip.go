package node

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

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
// first..min(first+100,last) zipped under the entry names
// "NOSODATA/BLOCKS/N.blk" (forward slashes), as the Pascal peers expect.
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
		w, err := zw.Create("NOSODATA/BLOCKS/" + codec.IntToStr(i) + ".blk")
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

// UnzipBlocks stores every "*.blk" entry of a received block zip into the
// blocks directory. Entry paths are reduced to their base name, which both
// accepts the Pascal naming and prevents path traversal (hardening).
func (n *Node) UnzipBlocks(data []byte) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, err
	}
	count := 0
	for _, f := range zr.File {
		name := filepath.Base(strings.ReplaceAll(f.Name, "\\", "/"))
		if !strings.HasSuffix(name, ".blk") || f.UncompressedSize64 > 64<<20 {
			continue
		}
		stem := strings.TrimSuffix(name, ".blk")
		if codec.StrToInt64Def(stem, -1) < 0 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return count, err
		}
		if err := os.WriteFile(filepath.Join(n.Lay.BlockDir, name), raw, 0o644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
