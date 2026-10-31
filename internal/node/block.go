package node

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
	"github.com/pasichDev/noso-node-go/internal/consensus"
	"github.com/pasichDev/noso-node-go/internal/crypto"
	"github.com/pasichDev/noso-node-go/internal/storage"
	"github.com/pasichDev/noso-node-go/internal/types"
)

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

// ---- the state transition shared by builder, validator and replay ---------
//
// FIX(C-03, M-11): the original computed a block's effect twice, once while
// building (mpblock.pas) and once while replaying (mpdisk.pas), and the two
// disagreed. Here a single set of functions applies an order and the block's
// closing payments; the proposer uses them to choose orders, every follower
// uses them to check the proposer's choice, so the result (and the summary
// file, byte for byte) is the same by construction.

var errState = errors.New("block does not apply to the current state")

func stateErr(format string, a ...any) error {
	return errors.New(errState.Error() + ": " + fmt.Sprintf(format, a...))
}

// applyOrder applies one user order (CUSTOM, TRFR, SNDGVT) to the pending
// block records and returns the fee the miner collects. o is in block form
// (Sender is the address). false means the order does not apply and nothing
// was changed.
func (n *Node) applyOrder(o types.Order, number int64) (fee int64, ok bool, err error) {
	addr := o.Address
	switch o.OrderType {
	case "TRFR":
		total, sum := consensus.CheckedAdd(o.AmmountFee, o.AmmountTrf)
		if !sum || !ValidReceiver(o.Receiver) || !n.Summary.ValidPay(addr, total, number) {
			return 0, false, nil
		}
		if !n.Summary.CreditTo(o.Receiver, o.AmmountTrf, number) {
			return 0, false, stateErr("credit of %s refused", o.Receiver)
		}
		return o.AmmountFee, true, nil
	case "CUSTOM":
		// FIX(C-06, M-01): exact fee, no amount, valid unused alias.
		f := consensus.GetCustFee(number)
		if o.AmmountFee != f || o.AmmountTrf != 0 || !ValidAlias(o.Receiver) || n.aliasTaken(o.Receiver, nil) {
			return 0, false, nil
		}
		if !n.Summary.CustomizationValid(addr, o.Receiver, number, false, f) {
			return 0, false, nil
		}
		return f, true, nil
	case "SNDGVT":
		// FIX(M-14): the owner's own key authorises the transfer, and the
		// fee counts only after the debit succeeded (mpblock.pas:217-229).
		f := consensus.GetCustFee(number)
		num, good := gvtNumber(o.Reference)
		if o.AmmountFee != f || o.AmmountTrf != 0 || !ValidReceiver(o.Receiver) || !good ||
			n.GVTs.Index(num).Owner != addr || !n.Summary.ValidPay(addr, f, number) {
			return 0, false, nil
		}
		if n.GVTs.ChangeOwner(num, addr, o.Receiver) != 0 {
			return 0, false, stateErr("gvt %d did not change owner", num)
		}
		return f, true, nil
	}
	return 0, false, nil
}

// gvtNumber accepts only the canonical decimal 0..99. FIX: the original read
// the reference with StrToIntDef, which also accepts "$05", "x05", " 5"...
func gvtNumber(ref string) (int, bool) {
	v, ok := codec.StrToInt64(ref)
	if !ok || v < 0 || v > 99 || codec.IntToStr(v) != ref {
		return 0, false
	}
	return int(v), true
}

// applyEnd applies the closing payments of block number: the project share,
// the masternode shares (each locked for 2016 blocks), the miner's remainder
// and the touch of the genesis account that records the block number.
func (n *Node) applyEnd(number int64, miner string, fees int64, mns []string) (dev, mnsPay, pow int64, newMNs int, err error) {
	reward := consensus.GetBlockReward(number)
	dev, mnsPay, _, pow, ok := consensus.Shares(number, reward, fees, len(mns))
	if !ok {
		return 0, 0, 0, 0, stateErr("amounts out of range")
	}
	credit := func(a string, v int64) error {
		if !n.Summary.CreditTo(a, v, number) {
			return stateErr("credit of %q refused", a)
		}
		return nil
	}
	if number == 0 {
		if err = credit(storage.GenesisAddress, 0); err != nil { // slot 0 holds the last operation
			return
		}
	}
	if number >= consensus.PoSBlockEnd {
		if err = credit(consensus.ProjectFunds, dev); err != nil {
			return
		}
	}
	if number >= consensus.MNBlockStart {
		for _, a := range mns {
			if err = credit(a, mnsPay); err != nil {
				return
			}
			if n.PSOs.AddLocked(a, int(number)) {
				newMNs++
			}
		}
	}
	if err = credit(miner, pow); err != nil {
		return
	}
	if err = credit(storage.GenesisAddress, 0); err != nil {
		return
	}
	return dev, mnsPay, pow, newMNs, nil
}

// ---- building ---------------------------------------------------------------

// BuildNewBlock mirrors BuildNewBlock (mpblock.pas:84-422). It returns
// (nil, nil) when the build is skipped (SkipBlocks, STOP mode, bad
// timestamps) exactly where Pascal merely logs.
//
// FIX(M-12): nothing is consumed before the block is on disk. The state files
// are snapshotted first and put back when any step fails, the pool and the
// masternode tables are only touched after success, so a failed build can be
// retried without paying twice.
func (n *Node) BuildNewBlock(number, timestamp int64, targetHash, miner, solution string) (*BuildResult, error) {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.buildLocked(number, timestamp, targetHash, miner, solution)
}

func (n *Node) buildLocked(number, timestamp int64, targetHash, miner, solution string) (*BuildResult, error) {
	if n.isCorrupt() {
		return nil, ErrCorrupt
	}
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

	prev := n.LastBlockData()
	prevHash := n.MyLastBlockHash()
	myLast := n.MyLastBlock()
	if number > 0 && timestamp < prev.TimeEnd {
		n.logf("console", "New block "+codec.IntToStr(number)+" : Invalid timestamp")
		return nil, nil
	}
	if timestamp > n.UTCTime()+5 {
		n.logf("console", "New block "+codec.IntToStr(number)+" : Invalid timestamp")
		return nil, nil
	}
	if number > 0 && number != myLast+1 {
		return nil, bad("cannot build block %d on top of %d", number, myLast)
	}
	sIdx, sw, sealed := n.sealer()
	if sealed && number > 0 {
		miner = crypto.GetAddressFromPublicKey(sw.PublicKey, 0)
	}

	startBlockTime := int64(consensus.GenesisStartTime)
	if number != 0 {
		startBlockTime = prev.TimeEnd + 1
	}
	if err := n.snapshot(codec.IntToStr(number)); err != nil {
		return nil, err
	}
	rollback := func(headerAdded bool) {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot(codec.IntToStr(number))
		if number > 0 {
			n.Blocks.Delete(number)
		}
		if headerAdded {
			n.Headers.RemoveLast()
		}
		n.SetMyLastBlock(myLast)
		n.UpdateMyData()
	}
	_ = n.Summary.Backup()
	_ = n.GVTs.Backup()
	n.Summary.ResetBlockRecords()

	lastTrxs := map[string]bool{}
	for _, o := range n.Blocks.Orders(myLast) {
		lastTrxs[o.TrfrID] = true
	}
	pool := n.PendingCopy()
	var list, ignored []types.Order
	var keys []string
	var minerFee int64
	var blockTrfrs, gvts int
	seen := map[string]bool{}
	if number > 0 {
		for _, ord := range pool {
			if ord.TimeStamp < prev.TimeStart || lastTrxs[ord.TrfrID] || seen[ord.TrfrID] {
				continue
			}
			if ord.TimeStamp+60 > timestamp || blockTrfrs >= consensus.MaxTransfersPerBlock ||
				(ord.OrderType == "SNDGVT" && gvts >= consensus.MaxGVTPerBlock) {
				if ord.TimeStamp < timestamp+600 {
					ignored = append(ignored, ord)
				}
				continue
			}
			key := ord.Sender
			if checkOrder(ord, prev, timestamp) != nil {
				continue
			}
			ord.Block = int32(number)
			ord.AssignSender(ord.Address)
			fee, ok, err := n.applyOrder(ord, number)
			if err != nil {
				rollback(false)
				return nil, err
			}
			if !ok {
				continue
			}
			seen[ord.TrfrID] = true
			minerFee += fee
			if ord.OrderType == "SNDGVT" {
				gvts++
			} else {
				blockTrfrs++
			}
			list = append(list, ord)
			keys = append(keys, key)
		}
	}

	// FIX(C-01): pending project payments in the configuration (NOSOPAY,
	// mpblock.pas:233-258) are no longer executed: configuration data cannot
	// move funds.

	// Masternodes: the list a follower can check by the chain alone.
	var mnsAddrs []string
	var mnsText string
	if number >= consensus.MNBlockStart {
		mnsText, mnsAddrs = n.paidMNs(myLast)
	}
	dev, mnsPay, pow, newMNs, err := n.applyEnd(number, miner, minerFee, mnsAddrs)
	if err != nil {
		rollback(false)
		return nil, err
	}
	if number >= consensus.PoSBlockEnd {
		list = append(list, createDevPaymentOrder(number, timestamp, dev, myLast))
		keys = append(keys, "")
	}

	h := types.BlockHeader{
		Number: number, TimeStart: startBlockTime, TimeEnd: timestamp,
		TimeTotal: int32(timestamp - startBlockTime), TrxTotales: int32(len(list)),
	}
	// FIX(8425): the proof-of-stake list is never filled, so nothing is paid
	// to stakers and the whole share stays with the miner. The original
	// divided by zero here and stopped (mpblock.pas:294-298); on a chain that
	// must keep growing that is replaced by this explicit rule.
	switch {
	case number == 0:
		h.Difficult = consensus.InitialBlockDiff
	case number < 53000:
		h.Difficult = 0
	default:
		h.Difficult = 0
	}
	h.TargetHash = codec.Truncate(targetHash, 32)
	mnsTotal := int64(len(mnsAddrs)) * mnsPay
	h.Solution = codec.Truncate(solution+" FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1 "+codec.IntToStr(pow)+" "+
		codec.IntToStr(mnsTotal)+" 0", 200)
	if number == 0 {
		h.Solution = ""
		h.LastBlockHash = "NOSO GENESYS BLOCK"
	} else {
		h.LastBlockHash = codec.Truncate(prevHash, 32)
	}
	if number >= 53000 {
		h.NxtBlkDiff = int32(len(mnsAddrs))
	}
	h.AccountMiner = codec.Truncate(miner, 40)
	h.MinerFee = minerFee
	h.Reward = consensus.GetBlockReward(number)

	blk := &storage.Block{Header: h, Orders: list, MNsPay: mnsPay, MNsAddrs: mnsAddrs}
	if number > 0 {
		blk.V2, blk.Keys = true, keys
		if sealed {
			sealBlock(blk, sw.PublicKey, sw.PrivateKey)
		}
	}
	_ = sIdx
	if err := n.Summary.UpdateChanges(); err != nil {
		rollback(false)
		return nil, err // FIX(M-12): stop on a failed write (nosounit.pas:549-553)
	}
	n.Summary.SetLastOp(number)
	if err := n.Blocks.Write(blk); err != nil {
		n.logf("exceps", "*****CRITICAL***** Error building block: "+codec.IntToStr(number))
		rollback(false)
		return nil, err // FIX(M-12): do not advance the chain on a failed write (mpblock.pas:536-542)
	}
	_ = n.ZipSummary()
	n.mu.Lock()
	n.myLastBlock = number
	n.mu.Unlock()
	n.UpdateMyData()
	n.Summary.SetHash()
	if !n.Headers.Add(number, n.MyLastBlockHash(), n.Summary.Hash()) {
		rollback(false)
		return nil, errHeaderWrite
	}
	n.persistDerived(number, gvts > 0)
	n.noteTip(number)
	n.pruneSnapshots(number)

	// Only now is the pool and the masternode state of this period consumed.
	n.replacePending(pool, ignored)
	if number >= consensus.MNBlockStart {
		n.MNFile.Save(mnsText)
	}
	n.ClearMNsChecks()
	n.ClearMNsList()
	n.ClearReceivedMNs()
	n.ClearReceivedOrderIDs()
	n.Wallet.ClearPendings()
	n.Headers.SetHash()
	if number > 0 && n.OnNewBlock != nil && n.serverActive() {
		n.OnNewBlock()
	}
	n.CheckForMyPending()
	expired := n.lastExpired
	n.logf("console", "Block built: "+codec.IntToStr(number))
	return &BuildResult{Block: blk, NewMNs: newMNs, ExpiredMNs: expired,
		PoWReward: pow, MNsReward: mnsPay, DevReward: dev}, nil
}

// persistDerived writes the files derived from the chain besides the
// summary: GVT owners, masternode locks and their expiry.
func (n *Node) persistDerived(number int64, gvtMoved bool) {
	if gvtMoved {
		n.GVTs.Save()
	}
	n.lastExpired = n.PSOs.ClearExpired(int(number))
	n.PSOs.Save(int(number))
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

// ---- replay -----------------------------------------------------------------

// AddBlockToSummary mirrors AddBlockToSumary (mpdisk.pas:660-738): the
// effect of block number on the summary is re-derived from the block file.
func (n *Node) AddBlockToSummary(number int64, saveAndUpdate bool) error {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.addBlockToSummaryLocked(number, saveAndUpdate)
}

func (n *Node) addBlockToSummaryLocked(number int64, saveAndUpdate bool) error {
	blk, err := n.Blocks.Read(number)
	if err != nil && blk == nil {
		blk = &storage.Block{Header: n.Blocks.Header(number), Orders: n.Blocks.Orders(number)}
	}
	if blk.V2 {
		if saveAndUpdate {
			n.Summary.ResetBlockRecords()
		}
		moved, err := n.applyBlockState(blk)
		if err != nil {
			return err
		}
		if saveAndUpdate {
			if err := n.Summary.UpdateChanges(); err != nil {
				return err
			}
		}
		n.persistDerived(number, moved)
		if number%1000 == 0 {
			_ = copyFile(n.Lay.Summary, n.Lay.MarksDir+"/"+codec.IntToStr(number)+".bak")
		}
		return nil
	}
	return n.replayLegacy(number, blk, err, saveAndUpdate)
}

// applyBlockState applies a stored (or received) V2 block to the pending
// records. Stateless rules are the validator's business; this enforces what
// depends on balances, ownership and aliases. It returns the number of
// masternodes newly locked.
func (n *Node) applyBlockState(b *storage.Block) (moved bool, err error) {
	h := b.Header
	var fees int64
	for i, o := range b.Orders {
		if o.OrderType == "PROJCT" {
			continue
		}
		fee, ok, err := n.applyOrder(o, h.Number)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, stateErr("order %d (%s) cannot be applied", i, o.OrderType)
		}
		if o.OrderType == "SNDGVT" {
			moved = true
		}
		fees += fee
	}
	if fees != h.MinerFee {
		return false, stateErr("miner fee %d, orders pay %d", h.MinerFee, fees)
	}
	if h.Number >= consensus.MNBlockStart {
		if err := n.checkMNs(b, h.Number); err != nil {
			return false, err
		}
	}
	_, mnsPay, _, _, err := n.applyEnd(h.Number, h.AccountMiner, fees, b.MNsAddrs)
	if err != nil {
		return false, err
	}
	if mnsPay != b.MNsPay {
		return false, stateErr("masternode pay %d, expected %d", b.MNsPay, mnsPay)
	}
	return moved, nil
}

// checkMNs: the masternode list of a block must be distinct, bounded and made
// of addresses that hold the stake (FIX(C-03): any list was accepted).
func (n *Node) checkMNs(b *storage.Block, number int64) error {
	if len(b.MNsAddrs) > consensus.MaxMasternodesPerBlock {
		return stateErr("%d masternodes", len(b.MNsAddrs))
	}
	seen := map[string]bool{}
	for _, a := range b.MNsAddrs {
		if seen[a] || !MNEligible(n, a, number) {
			return stateErr("masternode %q is duplicated or not eligible", a)
		}
		seen[a] = true
	}
	return nil
}

// replayLegacy is the replay of blocks without the V2 trailer (blocks of the
// original network). FIX(M-11): build and replay touch the same account; an
// unfunded transfer makes the block invalid instead of charging the miner.
func (n *Node) replayLegacy(number int64, blk *storage.Block, readErr error, saveAndUpdate bool) error {
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
		if readErr != nil {
			return readErr
		}
		for _, a := range blk.PosAddrs {
			n.Summary.CreditTo(a, blk.PosPay, number)
		}
		n.Summary.Pay(h.AccountMiner, int64(len(blk.PosAddrs))*blk.PosPay, number)
	}
	if number >= consensus.MNBlockStart {
		if readErr != nil {
			return readErr
		}
		for _, a := range blk.MNsAddrs {
			n.Summary.CreditTo(a, blk.MNsPay, number)
		}
		n.Summary.Pay(h.AccountMiner, int64(len(blk.MNsAddrs))*blk.MNsPay, number)
	}
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
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.completeSummaryLocked()
}

func (n *Node) completeSummaryLocked() error {
	if n.isCorrupt() {
		return ErrCorrupt
	}
	if n.Consensus != nil && codec.Copy(n.Summary.Hash(), 1, 5) == n.Consensus(17) {
		return nil
	}
	start := n.Summary.LastOp() + 1
	finish := n.MyLastBlock()
	if start > finish {
		return nil
	}
	n.logf("console", "Complete summary")
	// FIX: Pascal took the undo backup here, clobbering the one of the last
	// build when there was nothing to replay.
	if err := n.snapshot("complete"); err != nil {
		return err
	}
	for i := start; i <= finish; i++ {
		if err := n.addBlockToSummaryLocked(i, true); err != nil {
			// FIX(C-03): a block that cannot be replayed is removed together
			// with everything after it, and the summary is restored.
			_ = n.restoreSnapshot("complete")
			if n.removeBlocksLocked(i) < 0 {
				// FIX(H-04): the bad block lies below the finality horizon;
				// it cannot be removed on the word of local replay alone.
				n.markCorrupt()
				n.logf("exceps", "block "+codec.IntToStr(i)+" cannot be replayed and is final: chain data inconsistent")
				return errors.Join(ErrCorrupt, err)
			}
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
// is recreated and every block replayed in batches of 100. FIX: on a failed
// replay the previous summary, GVT and masternode-lock files are put back
// and the error is returned (the original always finished).
func (n *Node) RebuildSummary() error {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.rebuildSummaryLocked()
}

func (n *Node) rebuildSummaryLocked() error {
	if err := n.snapshot("rebuild"); err != nil {
		return err
	}
	fail := func(err error) error {
		n.Summary.ResetBlockRecords()
		_ = n.restoreSnapshot("rebuild")
		n.UpdateMyData()
		return err
	}
	last := n.MyLastBlock()
	goChain := false
	if blk, err := n.Blocks.Read(1); err == nil && blk.V2 {
		goChain = true
	}
	if goChain {
		// A chain born here: block 0 is replayed like any other and the
		// derived files start empty.
		n.Summary.CreateNew(false)
		_ = os.WriteFile(n.Lay.GVTs, nil, 0o644)
		n.GVTs.Reload()
		_ = os.Remove(n.Lay.PSOs)
		n.PSOs.Load()
		g := n.Blocks.Header(0)
		n.Summary.ResetBlockRecords()
		if _, _, _, _, err := n.applyEnd(0, g.AccountMiner, 0, nil); err != nil {
			return fail(err)
		}
		if err := n.Summary.UpdateChanges(); err != nil {
			return fail(err)
		}
		n.Summary.ResetBlockRecords()
	} else {
		n.Summary.CreateNew(storage.Exists(n.Lay.BlockFile(0)))
	}
	for i := int64(1); i <= last; i++ {
		if err := n.addBlockToSummaryLocked(i, false); err != nil {
			return fail(err)
		}
		if i%100 == 0 {
			if err := n.Summary.UpdateChanges(); err != nil {
				return fail(err)
			}
			n.Summary.ResetBlockRecords()
		}
	}
	if err := n.Summary.UpdateChanges(); err != nil {
		return fail(err)
	}
	n.Summary.ResetBlockRecords()
	n.UpdateMyData()
	n.Summary.CreateIndex()
	return nil
}

// UndoLastBlock mirrors UndoneLastBlock (mpblock.pas:692-744), restoring the
// state files of the snapshot taken before that block. A block at or below the
// finality horizon is never undone.
func (n *Node) UndoLastBlock() {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	n.undoLastLocked()
}

func (n *Node) undoLastLocked() {
	num := n.MyLastBlock()
	if num == 0 {
		return
	}
	if num <= n.Finalized() {
		n.logf("console", "Can not undo block "+codec.IntToStr(num))
		return
	}
	if n.ConStatus() == 3 {
		n.SetConStatus(2)
		n.ClearMNsChecks()
		n.ClearMNsList()
		n.ClearPending()
		n.ClearReceivedOrderIDs()
	}
	if n.hasSnapshot(codec.IntToStr(num)) {
		_ = n.restoreSnapshot(codec.IntToStr(num))
	} else {
		_ = n.Summary.Restore()
		n.Summary.CreateIndex()
		_ = n.GVTs.RestoreBackup()
	}
	n.Headers.RemoveLast()
	n.Blocks.Delete(num)
	n.SetMyLastBlock(n.Blocks.LastUpdated())
	n.UpdateMyData()
	n.logf("console", "Block undone: "+codec.IntToStr(num))
}

// MaxReorgDepth is the most blocks a node will delete on the word of its
// peers, counted from the highest tip it ever reached (FIX(H-04):
// RemoveBlocks, mpblock.pas:746-760, deleted any number of blocks and looped
// forever when upTo was 0).
const MaxReorgDepth = 20

// RemoveBlocks deletes the blocks from upTo upward, restores the state to
// just before upTo and returns how many were removed, or -1 when upTo is at
// or below the finality horizon (nothing is changed then). Block 0 is never
// removed.
func (n *Node) RemoveBlocks(upTo int64) int {
	n.chainMu.Lock()
	defer n.chainMu.Unlock()
	return n.removeBlocksLocked(upTo)
}

func (n *Node) removeBlocksLocked(upTo int64) int {
	if upTo < 1 {
		upTo = 1
	}
	last := n.Blocks.LastUpdated()
	if upTo <= n.Finalized() {
		return -1
	}
	if upTo > last {
		return 0
	}
	label := codec.IntToStr(upTo)
	haveSnap := n.hasSnapshot(label)
	removed := 0
	for b := last; b >= upTo; b-- {
		n.Blocks.Delete(b)
		removed++
	}
	for n.Headers.Height() >= int(upTo) && n.Headers.RemoveLast() {
	}
	n.SetMyLastBlock(n.Blocks.LastUpdated())
	if haveSnap {
		_ = n.restoreSnapshot(label)
	} else {
		_ = n.rebuildSummaryLocked()
	}
	n.UpdateMyData()
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
	if n.Summary.AliasTaken(alias) {
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
