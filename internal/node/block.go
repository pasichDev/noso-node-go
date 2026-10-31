package node

import (
	"errors"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

// ErrDivZero reproduces the EDivByZero Pascal raises in BuildNewBlock for
// blocks in [8425, 88500): the PoS address list is never filled, so
// PosReward := PosTotalReward div PoScount divides by zero
// (mpblock.pas:294-298).
var ErrDivZero = errors.New("division by zero (PoS payment, mpblock.pas:297)")

// BuildResult describes a built block.
type BuildResult struct {
	Block        *storage.Block
	NewMNs       int
	ExpiredMNs   int
	PoWReward    int64
	MNsReward    int64
	DevReward    int64
	ErrorMessage string
}

// CreateGenesis mirrors CrearBloqueCero (mpblock.pas:76-81).
func (n *Node) CreateGenesis() {
	_, _ = n.BuildNewBlock(0, consensus.GenesysTimeStamp, "", consensus.AdminHash, "")
}

func createDevPaymentOrder(number int64, timestamp, amount, myLast int64) types.Order {
	o := types.Order{Block: int32(number), OrderLines: 1, OrderType: "PROJCT", TimeStamp: timestamp - 1,
		Reference: "null", TrxLine: 1, Sender: "COINBASE", Address: "COINBASE",
		Receiver: consensus.ProjectFunds, AmmountTrf: amount, Signature: "COINBASE"}
	o.TrfrID = crypto.GetTransferHash(codec.IntToStr(o.TimeStamp) + "COINBASE" + consensus.ProjectFunds +
		codec.IntToStr(amount) + codec.IntToStr(myLast))
	o.OrderID = "1" + o.TrfrID // COMPAT: no GetOrderHash here (mpblock.pas:53)
	o.Normalize()
	return o
}

func createNosoPayOrder(number int64, from, to string, timestamp, amount, myLast int64) types.Order {
	o := types.Order{Block: int32(number), OrderLines: 1, OrderType: "TRFR", TimeStamp: timestamp - 1,
		Reference: "null", TrxLine: 1, Sender: from, Address: from, Receiver: to,
		AmmountTrf: amount, Signature: "Directive"}
	o.TrfrID = crypto.GetTransferHash(codec.IntToStr(o.TimeStamp) + "TRFR" + from +
		codec.IntToStr(amount) + codec.IntToStr(myLast))
	o.OrderID = crypto.GetOrderHash("1" + o.TrfrID)
	o.Normalize()
	return o
}

// BuildNewBlock mirrors BuildNewBlock (mpblock.pas:84-422). It returns
// (nil, nil) when the build is skipped (SkipBlocks, STOP mode, bad
// timestamps) exactly where Pascal merely logs.
func (n *Node) BuildNewBlock(number, timestamp int64, targetHash, miner, solution string) (*BuildResult, error) {
	opts := n.Options()
	if opts.SkipBlocks {
		return nil, nil
	}
	mode := n.CFG.Param(0)
	if mode == "STOP" {
		n.ClearPending()
		return nil, nil
	}
	if strings.Contains(mode, "EMPTY") {
		n.ClearPending()
	}
	n.mu.Lock()
	n.building = number
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.building = 0
		n.mu.Unlock()
	}()

	last := n.LastBlockData()
	if number > 0 && timestamp < last.TimeEnd {
		n.logf("console", "New block "+codec.IntToStr(number)+" : Invalid timestamp")
		return nil, nil
	}
	if timestamp > n.UTCTime()+5 {
		n.logf("console", "New block "+codec.IntToStr(number)+" : Invalid timestamp")
		return nil, nil
	}

	startBlockTime := int64(consensus.GenesisStartTime)
	if number != 0 {
		startBlockTime = last.TimeEnd + 1
	}
	_ = n.Summary.Backup()
	_ = n.GVTs.Backup()

	myLast := n.MyLastBlock()
	lastTrxs := n.Blocks.Orders(myLast)
	n.Summary.ResetBlockRecords()

	var list, ignored []types.Order
	var minerFee int64
	var blockTrfrs, gvtsTransferred int
	pool := n.PendingCopy()
	for _, ord := range pool {
		if ord.TimeStamp < last.TimeStart {
			continue
		}
		exists := false
		for _, lt := range lastTrxs {
			if lt.TrfrID == ord.TrfrID {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		if ord.TimeStamp+60 > timestamp || blockTrfrs >= 2000 {
			if ord.TimeStamp < timestamp+600 {
				ignored = append(ignored, ord)
			}
			continue
		}
		switch ord.OrderType {
		case "CUSTOM":
			opAddr := crypto.GetAddressFromPublicKey(ord.Sender, 0)
			// FIX(C-06, M-01): exact fee, no amount, valid unused alias.
			fee := consensus.GetCustFee(number)
			if ord.AmmountFee != fee || ord.AmmountTrf != 0 || !ValidAlias(ord.Receiver) ||
				n.aliasTaken(ord.Receiver, list) {
				continue
			}
			if n.Summary.CustomizationValid(opAddr, ord.Receiver, number, false, fee) {
				minerFee += fee
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
				blockTrfrs++
			}
		case "TRFR":
			opAddr := ord.Address
			// FIX(C-05): amounts are range checked and summed without overflow
			// (mpblock.pas:207 added them unchecked).
			total, ok := consensus.CheckedAdd(ord.AmmountFee, ord.AmmountTrf)
			if !ok || !ValidReceiver(ord.Receiver) {
				continue
			}
			if n.Summary.ValidPay(opAddr, total, number) {
				minerFee += ord.AmmountFee
				n.Summary.CreditTo(ord.Receiver, ord.AmmountTrf, number)
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
				blockTrfrs++
			}
		case "SNDGVT":
			// FIX(M-14): the owner's own key authorises the transfer, and the
			// fee counts only after the debit succeeded (mpblock.pas:217-229).
			opAddr := crypto.GetAddressFromPublicKey(ord.Sender, 0)
			fee := consensus.GetCustFee(number)
			if ord.AmmountFee != fee || ord.AmmountTrf != 0 || !ValidReceiver(ord.Receiver) {
				continue
			}
			if !n.Summary.ValidPay(opAddr, fee, number) {
				continue
			}
			if n.GVTs.ChangeOwner(int(codec.StrToIntDef(ord.Reference, 100)), opAddr, ord.Receiver) == 0 {
				minerFee += fee
				gvtsTransferred++
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
			} else {
				n.Summary.CreditTo(opAddr, fee, number) // refund
			}
		}
	}

	// FIX(C-01): pending project payments in the configuration (NOSOPAY,
	// mpblock.pas:233-258) are no longer executed: configuration data cannot
	// move funds.

	// Project funds payment.
	var devTotal int64
	if number >= consensus.PoSBlockEnd {
		devTotal = (consensus.GetBlockReward(number) + minerFee) * consensus.GetDevPercentage(number) / 10000
		n.Summary.CreditTo(consensus.ProjectFunds, devTotal, number)
		list = append(list, createDevPaymentOrder(number, timestamp, devTotal, myLast))
	}
	if gvtsTransferred > 0 {
		n.GVTs.Save()
	}
	n.SetPending(ignored)

	// PoS (never paid: the address list is empty).
	var posCount int
	var posReward, posTotal int64
	if number >= consensus.PoSBlockStart && number < consensus.PoSBlockEnd {
		return nil, ErrDivZero
	}

	// Masternodes.
	n.CreditMNVerifications()
	mnsText := n.MNsAddresses(myLast)
	n.MNFile.Save(mnsText)
	n.ClearMNsChecks()
	n.ClearMNsList()
	n.ClearReceivedMNs()
	var mnsAddrs []string
	var mnsReward, mnsTotal int64
	newMNs := 0
	if number >= consensus.MNBlockStart {
		for i := int64(1); ; i++ {
			p := codec.Parameter(mnsText, i)
			if p == "" {
				break
			}
			p = strings.ReplaceAll(p, ":", " ")
			mnsAddrs = append(mnsAddrs, codec.Truncate(codec.Parameter(p, 1), 32))
		}
		mnsTotal = (consensus.GetBlockReward(number) + minerFee) * consensus.GetMNsPercentage(number, n.CFG.Param(0)) / 10000
		if len(mnsAddrs) > 0 {
			mnsReward = mnsTotal / int64(len(mnsAddrs))
		}
		mnsTotal = int64(len(mnsAddrs)) * mnsReward
		for _, a := range mnsAddrs {
			n.Summary.CreditTo(a, mnsReward, number)
			if n.PSOs.AddLocked(a, int(number)) {
				newMNs++
			}
		}
	}

	n.ClearReceivedOrderIDs()

	powTotal := consensus.GetBlockReward(number) + minerFee - posTotal - mnsTotal - devTotal
	n.Summary.CreditTo(miner, powTotal, number)
	n.Summary.CreditTo(storage.GenesisAddress, 0, number)
	if err := n.Summary.UpdateChanges(); err != nil {
		return nil, err // FIX(M-12): stop on a failed write (nosounit.pas:549-553)
	}
	n.Summary.SetLastOp(number)
	n.Wallet.ClearPendings()

	h := types.BlockHeader{
		Number: number, TimeStart: startBlockTime, TimeEnd: timestamp,
		TimeTotal: int32(timestamp - startBlockTime), TrxTotales: int32(len(list)),
	}
	switch {
	case number == 0:
		h.Difficult = consensus.InitialBlockDiff
	case number < 53000:
		h.Difficult = 0
	default:
		h.Difficult = int32(posCount)
	}
	h.TargetHash = codec.Truncate(targetHash, 32)
	h.Solution = codec.Truncate(solution+" FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1 "+codec.IntToStr(powTotal)+" "+
		codec.IntToStr(mnsTotal)+" "+codec.IntToStr(posTotal), 200)
	if number == 0 {
		h.Solution = ""
		h.LastBlockHash = "NOSO GENESYS BLOCK"
	} else {
		h.LastBlockHash = codec.Truncate(n.MyLastBlockHash(), 32)
	}
	if number < 53000 {
		h.NxtBlkDiff = 0
	} else {
		h.NxtBlkDiff = int32(len(mnsAddrs))
	}
	h.AccountMiner = codec.Truncate(miner, 40)
	h.MinerFee = minerFee
	h.Reward = consensus.GetBlockReward(number)

	blk := &storage.Block{Header: h, Orders: list, PosPay: posReward, MNsPay: mnsReward, MNsAddrs: mnsAddrs}
	if err := n.Blocks.Write(blk); err != nil {
		n.logf("exceps", "*****CRITICAL***** Error building block: "+codec.IntToStr(number))
		return nil, err // FIX(M-12): do not advance the chain on a failed write (mpblock.pas:536-542)
	}
	_ = n.ZipSummary()

	n.mu.Lock()
	n.myLastBlock = number
	n.mu.Unlock()
	n.UpdateMyData()
	n.Summary.SetHash()
	if !n.Headers.Add(number, n.MyLastBlockHash(), n.Summary.Hash()) {
		return nil, errHeaderWrite
	}
	n.Headers.SetHash()
	if number > 0 && n.OnNewBlock != nil && n.serverActive() {
		n.OnNewBlock()
	}
	n.CheckForMyPending()
	expired := n.PSOs.ClearExpired(int(number))
	n.PSOs.Save(int(number))
	n.logf("console", "Block built: "+codec.IntToStr(number))
	return &BuildResult{Block: blk, NewMNs: newMNs, ExpiredMNs: expired,
		PoWReward: powTotal, MNsReward: mnsReward, DevReward: devTotal}, nil
}

// CheckForMyPending mirrors mpcoin.pas:306-338 (wallet pending totals).
func (n *Node) CheckForMyPending() {
	n.MontoIncoming, n.MontoOutgoing = 0, 0
	for _, o := range n.PendingCopy() {
		if idx := n.Wallet.IndexOf(o.Address); idx >= 0 {
			n.MontoOutgoing += o.AmmountFee + o.AmmountTrf
			n.Wallet.SetPending(idx, n.Wallet.At(idx).Pending+o.AmmountFee+o.AmmountTrf)
		}
		if n.Wallet.IndexOf(o.Receiver) >= 0 {
			n.MontoIncoming += o.AmmountTrf
		}
	}
}

// AddBlockToSummary mirrors AddBlockToSumary (mpdisk.pas:660-738): the
// effect of block number on the summary is re-derived from the block file.
// FIX(M-11): build and replay touch the same account; an unfunded transfer
// makes the block invalid instead of charging the miner.
func (n *Node) AddBlockToSummary(number int64, saveAndUpdate bool) error {
	blk, err := n.Blocks.Read(number)
	if err != nil && blk == nil {
		blk = &storage.Block{Header: n.Blocks.Header(number), Orders: n.Blocks.Orders(number)}
	}
	h := blk.Header
	if saveAndUpdate {
		n.Summary.ResetBlockRecords()
	}
	n.Summary.CreditTo(h.AccountMiner, h.Reward+h.MinerFee, number)
	gvts := 0
	for _, o := range blk.Orders {
		switch o.OrderType {
		case "CUSTOM":
			n.Summary.CustomizationValid(o.Sender, o.Receiver, number, true, consensus.GetCustFee(number))
		case "SNDGVT":
			gvts++
			n.Summary.Pay(o.Sender, consensus.GetCustFee(number), number)
			n.GVTs.ChangeOwner(int(codec.StrToIntDef(o.Reference, 100)), o.Sender, o.Receiver)
		case "TRFR":
			total, ok := consensus.CheckedAdd(o.AmmountFee, o.AmmountTrf)
			if !ok || !n.Summary.ValidPay(o.Sender, total, number) {
				// FIX(C-03): an unfunded transfer makes the block invalid
				// (mpdisk.pas:695-697 let the miner pay the fee instead).
				return errUnfunded
			}
			n.Summary.CreditTo(o.Receiver, o.AmmountTrf, number)
		case "PROJCT":
			n.Summary.CreditTo(consensus.ProjectFunds, o.AmmountTrf, number)
			n.Summary.Pay(h.AccountMiner, o.AmmountTrf, number)
		}
	}
	if number >= consensus.PoSBlockStart && number <= consensus.PoSBlockEnd {
		if err != nil {
			return err
		}
		for _, a := range blk.PosAddrs {
			n.Summary.CreditTo(a, blk.PosPay, number)
		}
		n.Summary.Pay(h.AccountMiner, int64(len(blk.PosAddrs))*blk.PosPay, number)
	}
	if number >= consensus.MNBlockStart {
		if err != nil {
			return err
		}
		for _, a := range blk.MNsAddrs {
			n.Summary.CreditTo(a, blk.MNsPay, number)
		}
		n.Summary.Pay(h.AccountMiner, int64(len(blk.MNsAddrs))*blk.MNsPay, number)
	}
	// FIX(M-11): the replay touches the same account as the build path
	// (mpdisk.pas:729 used AdminHash, mpblock.pas:355 the genesis account).
	n.Summary.CreditTo(storage.GenesisAddress, 0, number)
	if saveAndUpdate {
		if err := n.Summary.UpdateChanges(); err != nil {
			return err
		}
	}
	if number%1000 == 0 {
		_ = copyFile(n.Lay.Summary, n.Lay.MarksDir+"/"+codec.IntToStr(number)+".bak")
	}
	if gvts > 0 {
		n.GVTs.Save()
	}
	return nil
}

// CompleteSummary mirrors CompleteSumary (mpdisk.pas:631-657): replay the
// blocks after SummaryLastop until the last local block.
func (n *Node) CompleteSummary() error {
	if n.Consensus != nil && codec.Copy(n.Summary.Hash(), 1, 5) == n.Consensus(17) {
		return nil
	}
	start := n.Summary.LastOp() + 1
	finish := n.MyLastBlock()
	n.logf("console", "Complete summary")
	_ = n.Summary.Backup()
	for i := start; i <= finish; i++ {
		if err := n.AddBlockToSummary(i, true); err != nil {
			// FIX(C-03): a block that cannot be replayed is removed together
			// with everything after it, and the summary is restored.
			_ = n.Summary.Restore()
			n.Summary.CreateIndex()
			n.RemoveBlocks(i)
			n.UpdateMyData()
			return err
		}
	}
	n.Summary.SetLastOp(finish)
	n.UpdateMyData()
	_ = n.ZipSummary()
	n.logf("console", "Summary completed from "+codec.IntToStr(start-1)+" to "+codec.IntToStr(finish))
	return nil
}

// RebuildSummary mirrors RebuildSummary (mpdisk.pas:511-533): the summary
// is recreated (with block 0 premine when 0.blk exists) and every block
// replayed in batches of 100.
func (n *Node) RebuildSummary() error {
	n.Summary.CreateNew(storage.Exists(n.Lay.BlockFile(0)))
	last := n.MyLastBlock()
	for i := int64(1); i <= last; i++ {
		if err := n.AddBlockToSummary(i, false); err != nil {
			return err
		}
		if i%100 == 0 {
			n.Summary.UpdateChanges()
			n.Summary.ResetBlockRecords()
		}
	}
	n.Summary.UpdateChanges()
	n.UpdateMyData()
	n.Summary.CreateIndex()
	return nil
}

// UndoLastBlock mirrors UndoneLastBlock (mpblock.pas:692-744).
func (n *Node) UndoLastBlock() {
	num := n.MyLastBlock()
	n.mu.Lock()
	if num < n.undoHighest {
		n.mu.Unlock()
		n.logf("console", "Can not undo block "+codec.IntToStr(num))
		return
	}
	n.undoHighest = num
	n.mu.Unlock()
	if num == 0 {
		return
	}
	if n.ConStatus() == 3 {
		n.SetConStatus(2)
		n.ClearMNsChecks()
		n.ClearMNsList()
		n.ClearPending()
		n.ClearReceivedOrderIDs()
	}
	_ = n.Summary.Restore()
	n.Summary.CreateIndex()
	_ = n.GVTs.RestoreBackup()
	n.Headers.RemoveLast()
	n.Blocks.Delete(num)
	n.SetMyLastBlock(n.Blocks.LastUpdated())
	n.UpdateMyData()
	n.logf("console", "Block undone: "+codec.IntToStr(num))
}

// MaxReorgDepth is the most blocks a node will delete on the word of its
// peers. FIX(H-04): RemoveBlocks (mpblock.pas:746-760) deleted any number of
// blocks and looped forever when upTo was 0.
const MaxReorgDepth = 20

// RemoveBlocks deletes the block files from upTo upward and returns how many
// were removed, or -1 when that would exceed MaxReorgDepth (nothing is
// deleted then). Block 0 is never removed.
func (n *Node) RemoveBlocks(upTo int64) int {
	if upTo < 1 {
		upTo = 1
	}
	last := n.Blocks.LastUpdated()
	if last-upTo+1 > MaxReorgDepth {
		return -1
	}
	removed := 0
	for b := last; b >= upTo; b-- {
		n.Blocks.Delete(b)
		removed++
	}
	n.SetMyLastBlock(n.Blocks.LastUpdated())
	return removed
}

// NSLBlockOrders mirrors GEtNSLBlkOrdInfo (mpblock.pas:762-796).
func (n *Node) NSLBlockOrders(line string) string {
	res := "NSLBLKORD "
	p := strings.ToUpper(codec.Parameter(line, 1))
	var num int64
	if p == "LAST" {
		num = n.MyLastBlock()
	} else {
		num = codec.StrToIntDef(p, -1)
	}
	if num < 0 || num < n.MyLastBlock()-4000 || num > n.MyLastBlock() {
		return res + "ERROR"
	}
	res += codec.IntToStr(num) + " "
	for _, o := range n.Blocks.Orders(num) {
		if o.OrderType == "TRFR" {
			res += o.Sender + ":" + o.Receiver + ":" + codec.IntToStr(o.AmmountTrf) + ":" + o.Reference + ":" + o.OrderID + " "
		}
	}
	return codec.Trim(res)
}

var errHeaderWrite = nodeError("headers file write failed")

// aliasTaken reports whether an alias is already used in the summary or by an
// order already placed in this block. FIX(M-01).
func (n *Node) aliasTaken(alias string, list []types.Order) bool {
	if slot, _ := n.Summary.GetIndexPosition(alias, true); slot >= 0 {
		return true
	}
	for _, o := range list {
		if o.OrderType == "CUSTOM" && o.Receiver == alias {
			return true
		}
	}
	return false
}

var errUnfunded = nodeError("block contains an unfunded transfer")
