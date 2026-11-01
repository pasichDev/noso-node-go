package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// Block start heights (masterpaskalform.pas:606-608).
const (
	PoSBlockStart = 8425
	PoSBlockEnd   = 88500
	MNBlockStart  = 48010
)

// Block is the full content of one N.blk file.
type Block struct {
	Header types.BlockHeader
	Orders []types.Order
	// PoS tail, present when Number >= PoSBlockStart.
	PosPay   int64
	PosAddrs []string
	// Masternode tail, present when Number >= MNBlockStart.
	MNsPay   int64
	MNsAddrs []string
	// V2 marks a block that carries the authentication trailer: the full
	// public key of every order (Keys, parallel to Orders; empty for the
	// project payment) and, when sealed, the proposer's key and signature
	// over everything before the seal. Blocks without a trailer are legacy
	// (Pascal) blocks and stay readable.
	V2      bool
	Keys    []string
	SealKey string
	SealSig string
}

// TrailerMagic starts the authentication trailer of a V2 block.
const TrailerMagic = "NSG2"

// ErrBlockShort is returned for truncated block files.
var ErrBlockShort = errors.New("block file too short")

// Encode serialises a block exactly like GuardarBloque (mpblock.pas:503-545),
// followed by the V2 trailer when present.
func (b *Block) Encode() []byte {
	out := b.SigningBytes()
	if b.V2 {
		out = appendStr16(out, b.SealKey)
		out = appendStr16(out, b.SealSig)
	}
	return out
}

func appendStr16(out []byte, s string) []byte {
	out = append(out, byte(len(s)>>8), byte(len(s)))
	return append(out, s...)
}

// SigningBytes is everything the proposer's seal covers: the legacy body and
// the key list of the trailer, but not the seal itself.
func (b *Block) SigningBytes() []byte {
	out := b.Header.Encode()
	for _, o := range b.Orders {
		out = append(out, o.Encode()...)
	}
	if b.Header.Number >= PoSBlockStart {
		var t [12]byte
		codec.PutI64(t[:], b.PosPay)
		codec.PutI32(t[8:], int32(len(b.PosAddrs)))
		out = append(out, t[:]...)
		for _, a := range b.PosAddrs {
			rec := make([]byte, types.PosAddrSize)
			codec.PutShort(rec, 32, a)
			out = append(out, rec...)
		}
	}
	if b.Header.Number >= MNBlockStart {
		var t [12]byte
		codec.PutI64(t[:], b.MNsPay)
		codec.PutI32(t[8:], int32(len(b.MNsAddrs)))
		out = append(out, t[:]...)
		for _, a := range b.MNsAddrs {
			rec := make([]byte, types.PosAddrSize)
			codec.PutShort(rec, 32, a)
			out = append(out, rec...)
		}
	}
	if b.V2 {
		out = append(out, TrailerMagic...)
		out = append(out, byte(len(b.Keys)>>24), byte(len(b.Keys)>>16), byte(len(b.Keys)>>8), byte(len(b.Keys)))
		for _, k := range b.Keys {
			out = appendStr16(out, k)
		}
	}
	return out
}

// DecodeBlock parses a block file. The tails are parsed from the header's
// Number like the Pascal readers (GetBlockPoSes / GetBlockMNs).
func DecodeBlock(raw []byte) (*Block, error) {
	if len(raw) < types.HeaderSize {
		return nil, ErrBlockShort
	}
	b := &Block{Header: types.DecodeHeader(raw)}
	n := int(b.Header.TrxTotales)
	if n < 0 || n > (len(raw)-types.HeaderSize)/types.OrderSize {
		return nil, ErrBlockShort
	}
	pos := types.HeaderSize
	for i := 0; i < n; i++ {
		b.Orders = append(b.Orders, types.DecodeOrder(raw[pos:]))
		pos += types.OrderSize
	}
	tail := func() (int64, []string, bool) {
		if len(raw)-pos < 12 {
			return 0, nil, false
		}
		pay := codec.I64(raw[pos:])
		cnt := int(codec.I32(raw[pos+8:]))
		pos += 12
		if cnt < 0 || cnt > (len(raw)-pos)/types.PosAddrSize {
			return 0, nil, false
		}
		addrs := make([]string, 0, cnt)
		for i := 0; i < cnt; i++ {
			addrs = append(addrs, codec.GetShort(raw[pos:], 32))
			pos += types.PosAddrSize
		}
		return pay, addrs, true
	}
	if b.Header.Number >= PoSBlockStart {
		var ok bool
		if b.PosPay, b.PosAddrs, ok = tail(); !ok {
			return b, ErrBlockShort
		}
	}
	if b.Header.Number >= MNBlockStart {
		var ok bool
		if b.MNsPay, b.MNsAddrs, ok = tail(); !ok {
			return b, ErrBlockShort
		}
	}
	if len(raw)-pos >= 8 && string(raw[pos:pos+4]) == TrailerMagic {
		if err := b.decodeTrailer(raw[pos+4:]); err != nil {
			return b, err
		}
	}
	return b, nil
}

func (b *Block) decodeTrailer(raw []byte) error {
	str := func() (string, bool) {
		if len(raw) < 2 {
			return "", false
		}
		l := int(raw[0])<<8 | int(raw[1])
		if len(raw) < 2+l {
			return "", false
		}
		s := string(raw[2 : 2+l])
		raw = raw[2+l:]
		return s, true
	}
	if len(raw) < 4 {
		return ErrBlockShort
	}
	cnt := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	raw = raw[4:]
	if cnt < 0 || cnt > len(raw)/2 {
		return ErrBlockShort
	}
	for i := 0; i < cnt; i++ {
		k, ok := str()
		if !ok {
			return ErrBlockShort
		}
		b.Keys = append(b.Keys, k)
	}
	var ok1, ok2 bool
	if b.SealKey, ok1 = str(); !ok1 {
		return ErrBlockShort
	}
	if b.SealSig, ok2 = str(); !ok2 || len(raw) != 0 {
		return ErrBlockShort
	}
	b.V2 = true
	return nil
}

// Blocks is the BLOCKS directory.
type Blocks struct{ lay Layout }

// NewBlocks wraps a layout.
func NewBlocks(l Layout) *Blocks { return &Blocks{l} }

// Read loads block n.
func (bs *Blocks) Read(n int64) (*Block, error) {
	raw, err := os.ReadFile(bs.lay.BlockFile(n))
	if err != nil {
		return nil, err
	}
	return DecodeBlock(raw)
}

// Header mirrors LoadBlockDataHeader: a zero header when unreadable.
func (bs *Blocks) Header(n int64) types.BlockHeader {
	raw, err := os.ReadFile(bs.lay.BlockFile(n))
	if err != nil || len(raw) < types.HeaderSize {
		return types.BlockHeader{}
	}
	return types.DecodeHeader(raw)
}

// Orders mirrors GetBlockTrxs: orders of block n, empty when missing.
func (bs *Blocks) Orders(n int64) []types.Order {
	raw, err := os.ReadFile(bs.lay.BlockFile(n))
	if err != nil || len(raw) < types.HeaderSize {
		return nil
	}
	h := types.DecodeHeader(raw)
	cnt := int(h.TrxTotales)
	if cnt < 0 {
		return nil
	}
	var out []types.Order
	for i := 0; i < cnt && types.HeaderSize+(i+1)*types.OrderSize <= len(raw); i++ {
		out = append(out, types.DecodeOrder(raw[types.HeaderSize+i*types.OrderSize:]))
	}
	return out
}

// Write stores a block (SaveToFile).
func (bs *Blocks) Write(b *Block) error {
	return writeFileAtomic(bs.lay.BlockFile(b.Header.Number), b.Encode())
}

// Delete removes block n (TryDeleteFile).
func (bs *Blocks) Delete(n int64) {
	Crash("del-pre")
	_ = os.Remove(bs.lay.BlockFile(n))
	Crash("del-post")
}

// LastUpdated mirrors GetMyLastUpdatedBlock: the highest N among N.blk
// files below BLOCKS.
func (bs *Blocks) LastUpdated() int64 {
	var last int64
	_ = filepath.WalkDir(bs.lay.BlockDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".blk") {
			return nil
		}
		if filepath.Dir(p) != filepath.Clean(bs.lay.BlockDir) {
			return nil
		}
		name := strings.TrimSuffix(filepath.Base(p), ".blk")
		if v := codec.StrToInt64Def(name, 0); v > last {
			last = v
		}
		return nil
	})
	return last
}
