// Package types defines the on-disk and in-memory records of the Noso node
// with the exact packed-record byte layouts of the Free Pascal source.
package types

import "github.com/pasichDev/noso-node-go/internal/codec"

// Record sizes (bytes), derived from the packed record declarations.
const (
	SummarySize = 106 // nosounit.pas:18-24
	ResumenSize = 70  // nosoheaders.pas:18-22
	HeaderSize  = 368 // nosoblock.pas:25-40
	OrderSize   = 562 // nosogeneral.pas:26-41
	GVTSize     = 105 // nosogvts.pas:11-16
	WalletSize  = 626 // nosowallcon.pas:18-27
	PosAddrSize = 33  // mpblock TArrayPos = string[32], masterpaskalform.pas:186
	MNLockSize  = 40  // nosopsos.pas:28-31 (unpacked record: 33 + 3 pad + 4)
	PSOHdrSize  = 12  // nosopsos.pas:33-37
	DBRecSize   = 16  // nosoblock.pas:18-23
)

// Summary is TSummaryData: one account of sumary.psk.
type Summary struct {
	Hash    string // String[40]
	Custom  string // String[40]
	Balance int64
	Score   int64
	LastOP  int64
	raw     []byte
}

// DecodeSummary decodes a 106-byte record.
func DecodeSummary(b []byte) Summary {
	return Summary{
		Hash: codec.GetShort(b[0:], 40), Custom: codec.GetShort(b[41:], 40),
		Balance: codec.I64(b[82:]), Score: codec.I64(b[90:]), LastOP: codec.I64(b[98:]),
		raw: append([]byte(nil), b[:SummarySize]...),
	}
}

// Encode returns the 106-byte record.
func (s *Summary) Encode() []byte {
	b := make([]byte, SummarySize)
	copy(b, s.raw)
	codec.PutShort(b[0:], 40, s.Hash)
	codec.PutShort(b[41:], 40, s.Custom)
	codec.PutI64(b[82:], s.Balance)
	codec.PutI64(b[90:], s.Score)
	codec.PutI64(b[98:], s.LastOP)
	return b
}

// Resumen is ResumenData: one record of blchhead.nos.
type Resumen struct {
	Block     int32
	BlockHash string // String[32]
	SumHash   string // String[32]
}

// DecodeResumen decodes a 70-byte record.
func DecodeResumen(b []byte) Resumen {
	return Resumen{codec.I32(b), codec.GetShort(b[4:], 32), codec.GetShort(b[37:], 32)}
}

// Encode returns the 70-byte record.
func (r Resumen) Encode() []byte {
	b := make([]byte, ResumenSize)
	codec.PutI32(b, r.Block)
	codec.PutShort(b[4:], 32, r.BlockHash)
	codec.PutShort(b[37:], 32, r.SumHash)
	return b
}

// BlockHeader is BlockHeaderData, the first 368 bytes of every N.blk file.
type BlockHeader struct {
	Number        int64
	TimeStart     int64
	TimeEnd       int64
	TimeTotal     int32
	TimeLast20    int32
	TrxTotales    int32
	Difficult     int32
	TargetHash    string // String[32]
	Solution      string // String[200]
	LastBlockHash string // String[32]
	NxtBlkDiff    int32
	AccountMiner  string // String[40]
	MinerFee      int64
	Reward        int64
}

// DecodeHeader decodes a 368-byte header.
func DecodeHeader(b []byte) BlockHeader {
	return BlockHeader{
		Number: codec.I64(b[0:]), TimeStart: codec.I64(b[8:]), TimeEnd: codec.I64(b[16:]),
		TimeTotal: codec.I32(b[24:]), TimeLast20: codec.I32(b[28:]),
		TrxTotales: codec.I32(b[32:]), Difficult: codec.I32(b[36:]),
		TargetHash: codec.GetShort(b[40:], 32), Solution: codec.GetShort(b[73:], 200),
		LastBlockHash: codec.GetShort(b[274:], 32), NxtBlkDiff: codec.I32(b[307:]),
		AccountMiner: codec.GetShort(b[311:], 40), MinerFee: codec.I64(b[352:]),
		Reward: codec.I64(b[360:]),
	}
}

// Encode returns the 368-byte header.
func (h BlockHeader) Encode() []byte {
	b := make([]byte, HeaderSize)
	codec.PutI64(b[0:], h.Number)
	codec.PutI64(b[8:], h.TimeStart)
	codec.PutI64(b[16:], h.TimeEnd)
	codec.PutI32(b[24:], h.TimeTotal)
	codec.PutI32(b[28:], h.TimeLast20)
	codec.PutI32(b[32:], h.TrxTotales)
	codec.PutI32(b[36:], h.Difficult)
	codec.PutShort(b[40:], 32, h.TargetHash)
	codec.PutShort(b[73:], 200, h.Solution)
	codec.PutShort(b[274:], 32, h.LastBlockHash)
	codec.PutI32(b[307:], h.NxtBlkDiff)
	codec.PutShort(b[311:], 40, h.AccountMiner)
	codec.PutI64(b[352:], h.MinerFee)
	codec.PutI64(b[360:], h.Reward)
	return b
}

// Order is TOrderData (nosogeneral.pas:26-41). Assign fields through
// Normalize (or DecodeOrder / ParseOrder) so ShortString truncation is
// applied exactly like Pascal assignments do.
type Order struct {
	Block      int32
	OrderID    string // String[64]
	OrderLines int32
	OrderType  string // String[6]
	TimeStamp  int64
	Reference  string // String[64]
	TrxLine    int32
	Sender     string // String[120]
	Address    string // String[40]
	Receiver   string // String[40]
	AmmountFee int64
	AmmountTrf int64
	Signature  string // String[120]
	TrfrID     string // String[64]
}

// Normalize truncates every string field to its ShortString capacity.
func (o *Order) Normalize() {
	o.OrderID = codec.Truncate(o.OrderID, 64)
	o.OrderType = codec.Truncate(o.OrderType, 6)
	o.Reference = codec.Truncate(o.Reference, 64)
	o.Sender = codec.Truncate(o.Sender, 120)
	o.Address = codec.Truncate(o.Address, 40)
	o.Receiver = codec.Truncate(o.Receiver, 40)
	o.Signature = codec.Truncate(o.Signature, 120)
	o.TrfrID = codec.Truncate(o.TrfrID, 64)
}

// DecodeOrder decodes a 562-byte order record.
func DecodeOrder(b []byte) Order {
	return Order{
		Block: codec.I32(b[0:]), OrderID: codec.GetShort(b[4:], 64), OrderLines: codec.I32(b[69:]),
		OrderType: codec.GetShort(b[73:], 6), TimeStamp: codec.I64(b[80:]),
		Reference: codec.GetShort(b[88:], 64), TrxLine: codec.I32(b[153:]),
		Sender: codec.GetShort(b[157:], 120), Address: codec.GetShort(b[278:], 40),
		Receiver: codec.GetShort(b[319:], 40), AmmountFee: codec.I64(b[360:]),
		AmmountTrf: codec.I64(b[368:]), Signature: codec.GetShort(b[376:], 120),
		TrfrID: codec.GetShort(b[497:], 64),
	}
}

// Encode returns the 562-byte record.
func (o Order) Encode() []byte {
	b := make([]byte, OrderSize)
	codec.PutI32(b[0:], o.Block)
	codec.PutShort(b[4:], 64, o.OrderID)
	codec.PutI32(b[69:], o.OrderLines)
	codec.PutShort(b[73:], 6, o.OrderType)
	codec.PutI64(b[80:], o.TimeStamp)
	codec.PutShort(b[88:], 64, o.Reference)
	codec.PutI32(b[153:], o.TrxLine)
	codec.PutShort(b[157:], 120, o.Sender)
	codec.PutShort(b[278:], 40, o.Address)
	codec.PutShort(b[319:], 40, o.Receiver)
	codec.PutI64(b[360:], o.AmmountFee)
	codec.PutI64(b[368:], o.AmmountTrf)
	codec.PutShort(b[376:], 120, o.Signature)
	codec.PutShort(b[497:], 64, o.TrfrID)
	return b
}

// GVT is TGVT, one record of gvts.psk.
type GVT struct {
	Number  string // String[2]
	Owner   string // String[32]
	Hash    string // String[64]
	Control int32
	raw     []byte
}

// DecodeGVT decodes a 105-byte record.
func DecodeGVT(b []byte) GVT {
	return GVT{codec.GetShort(b[0:], 2), codec.GetShort(b[3:], 32), codec.GetShort(b[36:], 64),
		codec.I32(b[101:]), append([]byte(nil), b[:GVTSize]...)}
}

// Encode returns the 105-byte record.
func (g GVT) Encode() []byte {
	b := make([]byte, GVTSize)
	copy(b, g.raw)
	codec.PutShort(b[0:], 2, g.Number)
	codec.PutShort(b[3:], 32, g.Owner)
	codec.PutShort(b[36:], 64, g.Hash)
	codec.PutI32(b[101:], g.Control)
	return b
}

// Wallet is WalletData, one record of wallet.pkw.
type Wallet struct {
	Hash       string // String[40]
	Custom     string // String[40]
	PublicKey  string // String[255]
	PrivateKey string // String[255]
	Balance    int64
	Pending    int64
	Score      int64
	LastOP     int64
	raw        []byte
}

// DecodeWallet decodes a 626-byte record.
func DecodeWallet(b []byte) Wallet {
	return Wallet{
		Hash: codec.GetShort(b[0:], 40), Custom: codec.GetShort(b[41:], 40),
		PublicKey: codec.GetShort(b[82:], 255), PrivateKey: codec.GetShort(b[338:], 255),
		Balance: codec.I64(b[594:]), Pending: codec.I64(b[602:]),
		Score: codec.I64(b[610:]), LastOP: codec.I64(b[618:]),
		raw: append([]byte(nil), b[:WalletSize]...),
	}
}

// Encode returns the 626-byte record.
func (w Wallet) Encode() []byte {
	b := make([]byte, WalletSize)
	copy(b, w.raw)
	codec.PutShort(b[0:], 40, w.Hash)
	codec.PutShort(b[41:], 40, w.Custom)
	codec.PutShort(b[82:], 255, w.PublicKey)
	codec.PutShort(b[338:], 255, w.PrivateKey)
	codec.PutI64(b[594:], w.Balance)
	codec.PutI64(b[602:], w.Pending)
	codec.PutI64(b[610:], w.Score)
	codec.PutI64(b[618:], w.LastOP)
	return b
}

// MNLock is TMNsLock, a locked masternode of psos.dat.
type MNLock struct {
	Address string // String[32]
	Expire  int32
}

// DecodeMNLock decodes a 40-byte record.
func DecodeMNLock(b []byte) MNLock {
	return MNLock{codec.GetShort(b[0:], 32), codec.I32(b[36:])}
}

// Encode returns the 40-byte record (padding bytes are zero).
func (m MNLock) Encode() []byte {
	b := make([]byte, MNLockSize)
	codec.PutShort(b[0:], 32, m.Address)
	codec.PutI32(b[36:], m.Expire)
	return b
}

// DBRecord is TDBRecord of blocks_db.nos.
type DBRecord struct{ Block, OrderID, Source, Target int32 }

// Encode returns the 16-byte record.
func (d DBRecord) Encode() []byte {
	b := make([]byte, DBRecSize)
	codec.PutI32(b[0:], d.Block)
	codec.PutI32(b[4:], d.OrderID)
	codec.PutI32(b[8:], d.Source)
	codec.PutI32(b[12:], d.Target)
	return b
}

// DecodeDBRecord decodes a 16-byte record.
func DecodeDBRecord(b []byte) DBRecord {
	return DBRecord{codec.I32(b), codec.I32(b[4:]), codec.I32(b[8:]), codec.I32(b[12:])}
}
