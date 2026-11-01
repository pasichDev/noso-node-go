package storage

import (
	"os"
	"sync"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// BlocksDB is NOSODATA/BLOCKS/DB/blocks_db.nos (nosoblock.pas:84-321): a
// flat file of 16-byte TDBRecord entries (block, order, source, target
// hashes) and an in-memory index from the order hash to block numbers.
type BlocksDB struct {
	mu    sync.Mutex
	path  string
	index map[int32][]int32
}

// OpenBlocksDB creates the file when missing and loads the index.
func OpenBlocksDB(path string) *BlocksDB {
	d := &BlocksDB{path: path, index: map[int32][]int32{}}
	if !Exists(path) {
		_ = writeFileAtomic(path, nil)
	}
	d.dropTornTail()
	d.LoadIndex()
	return d
}

// DBIndex mirrors nosoblock.pas:180-188 with IDHash (SHA-256, FIX(M-13))
// instead of MD5: the hash text is converted with B16ToB58 (signed quirk
// included), characters 2..7 are read as Base58 and reduced modulo 100000.
// COMPAT BREAK: an existing blocks_db.nos written by the Pascal node holds
// MD5-based indexes that this function does not find; rebuild it.
func DBIndex(text string) int32 {
	t := crypto.B16ToB58(crypto.IDHash(text))
	sub := codec.Copy(t, 2, 6)
	v, _ := codec.StrToInt64(crypto.B58ToB10(sub))
	return int32(v % 100000)
}

// dropTornTail truncates a partial last record (crash during an append).
// Records are fixed-size, so a stray tail would misalign every later record
// (re2 #10). Headers.Add handles the same case by writing at the record
// boundary.
func (d *BlocksDB) dropTornTail() {
	if st, err := os.Stat(d.path); err == nil && st.Size()%types.DBRecSize != 0 {
		_ = os.Truncate(d.path, st.Size()/types.DBRecSize*types.DBRecSize)
	}
}

// LoadIndex mirrors CreateOrderIDIndex.
func (d *BlocksDB) LoadIndex() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.index = map[int32][]int32{}
	raw, err := os.ReadFile(d.path)
	if err != nil {
		return
	}
	for i := 0; i+types.DBRecSize <= len(raw); i += types.DBRecSize {
		r := types.DecodeDBRecord(raw[i:])
		d.index[r.OrderID] = append(d.index[r.OrderID], r.Block)
	}
}

// writeTail writes buf at the last whole record boundary (over a torn tail),
// syncs the file and closes it; the first error of any step is returned. The
// caller holds d.mu.
func (d *BlocksDB) writeTail(buf []byte) (err error) {
	f, err := os.OpenFile(d.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err = f.WriteAt(buf, st.Size()/types.DBRecSize*types.DBRecSize); err != nil {
		return err
	}
	return syncFile(f)
}

// Add mirrors AddRecordToDBFile. The record is written at the record boundary
// (over a torn tail) and synced; the index is updated only if the write
// succeeded.
func (d *BlocksDB) Add(block, order, source, target int32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.writeTail(types.DBRecord{Block: block, OrderID: order, Source: source, Target: target}.Encode()); err != nil {
		return false
	}
	d.index[order] = append(d.index[order], block)
	return true
}

// RollbackTo drops every record of a block above block and rebuilds the index.
// A reorganisation must call it with the new tip's parent before the
// replacement blocks are indexed; Update only ever indexes upwards, so stale
// records of the abandoned branch would stay (re2 #10).
func (d *BlocksDB) RollbackTo(block int32) error {
	d.mu.Lock()
	raw, err := os.ReadFile(d.path)
	if err != nil {
		d.mu.Unlock()
		return err
	}
	keep := 0
	for i := 0; i+types.DBRecSize <= len(raw); i += types.DBRecSize {
		if types.DecodeDBRecord(raw[i:]).Block > block {
			break
		}
		keep = i + types.DBRecSize
	}
	if keep < len(raw) {
		err = writeFileAtomic(d.path, raw[:keep])
	}
	d.mu.Unlock()
	d.LoadIndex()
	return err
}

// LastBlock mirrors GetDBLastBlock (0 for an empty file). Only the last record
// is read.
func (d *BlocksDB) LastBlock() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := os.Open(d.path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }() // read only: nothing can be lost by a failed close
	st, err := f.Stat()
	if err != nil || st.Size() < types.DBRecSize {
		return 0
	}
	buf := make([]byte, types.DBRecSize)
	if _, err := f.ReadAt(buf, (st.Size()/types.DBRecSize-1)*types.DBRecSize); err != nil {
		return 0
	}
	return int(types.DecodeDBRecord(buf).Block)
}

// Records mirrors GetDBRecords.
func (d *BlocksDB) Records() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := os.Stat(d.path)
	if err != nil {
		return 0
	}
	return int(st.Size() / types.DBRecSize)
}

// Blocks returns the candidate blocks for an order id (GetDBArray).
func (d *BlocksDB) Blocks(orderID string) []int32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]int32(nil), d.index[DBIndex(orderID)]...)
}

// AddBlock records every order of a block with one write and one sync. The
// block must be above everything recorded (RollbackTo first on a reorg).
func (d *BlocksDB) AddBlock(block int32, orders []types.Order) error {
	var buf []byte
	var ids []int32
	for _, o := range orders {
		if o.OrderType == "" {
			continue
		}
		id := DBIndex(o.OrderID)
		buf = append(buf, types.DBRecord{Block: block, OrderID: id, Source: DBIndex(o.Address), Target: DBIndex(o.Receiver)}.Encode()...)
		ids = append(ids, id)
	}
	if len(buf) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.writeTail(buf); err != nil {
		return err
	}
	for _, id := range ids {
		d.index[id] = append(d.index[id], block)
	}
	return nil
}

// Update mirrors UpdateBlockDatabase: every block after the last indexed one,
// up to upTo, is added.
func (d *BlocksDB) Update(bs *Blocks, upTo int64) error {
	for b := int64(d.LastBlock()) + 1; b <= upTo; b++ {
		if err := d.AddBlock(int32(b), bs.Orders(b)); err != nil {
			return err
		}
	}
	return nil
}

// BlockFromOrder mirrors GetBlockFromOrder: the block holding the order or -1.
func (d *BlocksDB) BlockFromOrder(bs *Blocks, orderID string) int {
	for _, b := range d.Blocks(orderID) {
		for _, o := range bs.Orders(int64(b)) {
			if o.OrderID == orderID {
				return int(o.Block)
			}
		}
	}
	return -1
}

// FindOrder mirrors GetOrderFromDB.
func (d *BlocksDB) FindOrder(bs *Blocks, orderID string) (types.Order, bool) {
	for _, b := range d.Blocks(orderID) {
		for _, o := range bs.Orders(int64(b)) {
			if o.OrderID == orderID {
				return o, true
			}
		}
	}
	return types.Order{}, false
}
