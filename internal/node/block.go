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
			if n.Summary.CustomizationValid(opAddr, ord.Receiver, number, false) {
				minerFee += ord.AmmountFee
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
				blockTrfrs++
			}
		case "TRFR":
			opAddr := ord.Address
			if n.Summary.ValidPay(opAddr, ord.AmmountFee+ord.AmmountTrf, number) {
				minerFee += ord.AmmountFee
				n.Summary.CreditTo(ord.Receiver, ord.AmmountTrf, number)
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
				blockTrfrs++
			}
		case "SNDGVT":
			if ord.Sender != consensus.AdminPubKey {
				break
			}
			opAddr := crypto.GetAddressFromPublicKey(ord.Sender, 0)
			if n.Summary.BalanceIndexed(opAddr) < ord.AmmountFee {
				continue
			}
			if n.GVTs.ChangeOwner(int(codec.StrToIntDef(ord.Reference, 100)), opAddr, ord.Receiver) == 0 {
				minerFee += ord.AmmountFee
				gvtsTransferred++
				n.Summary.ValidPay(opAddr, ord.AmmountFee, number)
				ord.Block = int32(number)
				ord.Sender = codec.Truncate(opAddr, 120)
				list = append(list, ord)
			}
		}
	}

	// Project payments from the CFG (mpblock.pas:233-258).
	if pay := n.CFG.Param(6); pay != "" {
		pay = strings.ReplaceAll(pay, ":", "")
		pay = strings.ReplaceAll(pay, ",", " ")
		if codec.StrToIntDef(codec.Parameter(pay, 0), 0) == number {
			src, dst := codec.Parameter(pay, 1), codec.Parameter(pay, 2)
			if crypto.IsValidHashAddress(dst) && crypto.IsValidHashAddress(src) {
				amt := codec.StrToInt64Def(codec.Parameter(pay, 3), 0)
				if amt > 0 && n.Summary.ValidPay(src, amt, number) {
					n.Summary.CreditTo(dst, amt, number)
					list = append(list, createNosoPayOrder(number, src, dst, timestamp, amt, myLast))
					_ = n.CFG.Remove(n.CFG.Param(6), 6)
				}
			}
		}
	}

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
	n.Summary.UpdateChanges()
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
	}
	_ = n.ZipSummary()

	n.mu.Lock()
	n.myLastBlock = number
	n.mu.Unlock()
	n.UpdateMyData()
	n.Summary.SetHash()
	n.Headers.Add(number, n.MyLastBlockHash(), n.Summary.Hash())
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
// COMPAT: the rebuild path touches AdminHash (CreditTo(AdminHash,0,N)) while
// the build path touches the genesis account; both quirks are kept, so a
// summary completed from blocks differs from one built live by the
// presence/LastOP of the AdminHash account.
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
			n.Summary.CustomizationValid(o.Sender, o.Receiver, number, true)
		case "SNDGVT":
			gvts++
			n.Summary.Pay(o.Sender, consensus.GetCustFee(number), number)
			n.GVTs.ChangeOwner(int(codec.StrToIntDef(o.Reference, 100)), o.Sender, o.Receiver)
		case "TRFR":
			if n.Summary.ValidPay(o.Sender, o.AmmountFee+o.AmmountTrf, number) {
				n.Summary.CreditTo(o.Receiver, o.AmmountTrf, number)
			} else {
				n.Summary.Pay(h.AccountMiner, o.AmmountFee, number)
			}
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
	n.Summary.CreditTo(consensus.AdminHash, 0, number)
	if saveAndUpdate {
		n.Summary.UpdateChanges()
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
	for i := start; i <= finish; i++ {
		if err := n.AddBlockToSummary(i, true); err != nil {
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

// RemoveBlocks mirrors RemoveBlocks (mpblock.pas:746-760): delete every
// block file from upTo upward; returns the number removed.
func (n *Node) RemoveBlocks(upTo int64) int {
	removed := 0
	for {
		last := n.Blocks.LastUpdated()
		if last >= upTo {
			n.Blocks.Delete(last)
			removed++
		}
		if last < upTo {
			break
		}
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
