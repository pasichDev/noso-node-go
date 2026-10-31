# Consensus

## Constants

| Name | Value | Source |
|---|---|---|
| Block period | 600 s | `SecondsPerBlock` |
| Premine (block 0 reward) | 1030390730000 (10303.9073 NOSO) | `PremineAmount` |
| Initial reward | 5000000000 | `InitialReward` |
| Halving | every 210000 blocks, 10 halvings; zero from block 2310000 | `GetBlockReward` |
| Amounts | integers, 8 decimals | |
| PoS start / end | 8425 / 88500 | `PoSBlockStart`, `PoSBlockEnd` |
| Masternode payments start | 48010 | `MNBlockStart` |
| Masternode lock | 2016 blocks | `MNsLockExpireLapse` |
| Project funds address | `NpryectdevepmentfundsGE` | |
| Genesis miner (history only) | `AdminHash`, no key is known for it | |

Reward at the boundaries (tests in `internal/consensus/rules_test.go`):
block 0 = 1030390730000, 1..209999 = 5000000000, 210000 = 2500000000,
420000 = 1250000000, and the last paid period (blocks 2100000..2309999)
yields `5000000000 div 1024 = 4882812` (truncated). Block 2310000 and above
pay 0. The supply function (`GetSupply`) follows the halving schedule (the original returned 0 from block 420000, L-06).

## Percentages (basis points of reward + fees)

* Masternodes: from 48010, `2000 + ((block-48010) div 4000) * 100`, plus
  1000 from 88400, capped at 6000; `MNSONLY` in the mode field gives 9000.
* PoS: 1000 for 8425..39999, then `1000 + ((block-39000) div 1000) * 100`
  capped at 2000, 0 from 88400.
* Project: 1000 from 88400.
* The miner (here always the project funds address, see below) gets the rest.

All divisions truncate (Int64 `div`).

## Trust model

The chain is proof of authority. There is no mining.

* **Proposers.** `NOSODATA/proposers.txt` lists the public keys (one per line,
  in rank order) that may seal blocks. It is chain configuration: every node
  of a chain must hold the same list in the same order (`Node.SetProposers`).
  Block 0 does not commit to it. A node with no list accepts no block from a
  peer (it fails closed) and, if asked to build, builds unsealed blocks of a
  standalone chain that nobody can join.
* **Turns.** The turn holder of a block time is proposer `(TimeEnd / 600) mod k`.
  Turns follow the clock, so a proposer that is offline costs only its own
  slots: the next boundary has another turn holder and blocks may skip slots.
  Honest nodes build only in their turn (`Node.InTurn`).
* **Seal.** A proposer signs the whole block (header, orders, tails and the
  public keys of the orders) under the domain `BLOCKSEAL1`. The miner of the
  block must be the proposer's own address: block rewards are paid to
  proposers, which is also what puts spendable coins into a fresh chain (the
  premine sits on `AdminHash`, whose key nobody holds).
* **What a proposer cannot do.** Spend an account whose key it lacks, repeat
  an order, mint coins, pay a masternode that is not staked, or pay more than
  the derived share: every follower checks all of it (below).
* **What it can do.** Choose which pending orders to include (censor or
  reorder), and sign two different blocks for its slot. The second case is
  settled by the fork rule; before it is settled a payment can be reversed
  inside the reorganisation window (20 blocks). Treat a payment as final
  after 20 blocks, not one.

## Fork choice (M-10)

Every valid block adds a weight: `k - rank` where `rank` is the distance of its
proposer from the turn holder (`BlockWeight`); with one proposer every block
weighs 1. A branch from a common block is preferred when its total weight is
larger, and on a tie when its tip hash is lower (`Preferred`). Both inputs are
facts about validated blocks, never votes. A node does not delete a block unless
a fully validated branch that is preferred is in hand. A lower tip hash can be
ground only among blocks of equal weight that an authorised key may sign.

The seeds' vote (`NODESTATUS`) now only tells a node where to look. A different
tip hash makes it ask for blocks from before its tip (`Node.ProbeFork`,
`BlocksRequestFrom`); `Node.AcceptBlocks` does the rest.

Reorganisation depth is bounded against the highest tip the node ever reached
(`highwater.seq`): no block more than 20 below it is replaced, whether in one
call or in many. `Finalized()` is that height. Rolling back restores the
summary, GVT and lock files from per-block snapshots (`NOSODATA/UNDO/N`, the
last 32 blocks), so a depth-k reorganisation ends with exactly the files of a
node that only saw the winning branch (tested).

## Block format

`N.blk` is the original layout (header, 562-byte orders, PoS tail from 8425,
masternode tail from 48010) followed by a trailer: `"NSG2"`, the count and the
full public key of every order (empty for the project payment), then the
proposer key and signature. Block 0 has no trailer. Blocks without a trailer
(the original network) stay readable and are replayed by the old rules; a
peer's block without a trailer is refused. The order record still carries the
sender address in `Sender`, so readers of the record are unchanged. The file
must be exactly the canonical encoding of what it decodes to.

## Validation of a received block

Stateless (`ValidateBlock`): number, parent hash, `TimeStart = prev.TimeEnd+1`,
`TimeEnd` a multiple of 600 not in the future, trailer and seal, miner is the
proposer, reward, no PoS payment, per order: type, amounts in range, the
order time inside `[prev.TimeStart, TimeEnd-60]`, key belongs to the address,
signature over every field, `TrfrID` derived, receiver/alias/GVT shape, no
repeated id (also against the previous block), caps (2000 `TRFR`+`CUSTOM`, 100
`SNDGVT`, the derived project payment last from block 88500), fee total, the
masternode pay equals `share / count` exactly.

Stateful (`applyBlockState`, the same functions the builder uses): `TRFR`
needs the funds; `CUSTOM` the funds and a free alias; `SNDGVT` ownership and the
fee; masternodes are distinct, valid and hold the stake. Any failure puts the
files back and refuses the block. Shares use `consensus.Shares` with 128-bit
intermediate products and do not read the local `CFG` mode (`MNSONLY` is
ignored). The order selection of the builder and the check of the follower are
the same code, so an honest block is never refused; a test builds 2000 `TRFR`
plus 3 `SNDGVT` at heights 100 and 88499 and applies them on a second node.

## Building a block (`Node.BuildNewBlock`)

Everything is under the chain lock, shared with block acceptance and with the
console commands `undoblock`, `rebuildsum` and `completesum`.

1. Skip when `SkipBlocks`; in mode `STOP` clear the pool and skip; in mode
   containing `EMPTY` clear the pool and continue.
2. The timestamp must not be before the last block's end nor more than 5 s in
   the future.
3. The summary, GVT and lock files are snapshotted.
4. Pending orders, in pool order, are re-checked completely (signature
   included) and applied. Skipped: older than the last block start, already in
   the last block, younger than 60 s before the block time, or past the caps
   (young ones stay in the pool).
5. Masternode list: reported nodes with enough validations that are valid,
   distinct and hold the stake at that height.
6. Closing payments (`applyEnd`): project share from 88500, masternode shares
   (each locked for 2016 blocks), the proposer gets the rest, the genesis
   account receives 0 so its `LastOP` is the block number.
7. Header, block file, headers record. On any failure the files are restored
   and the pool and masternode tables are left as they were.

Proof of stake is never paid: from 8425 the original divided by zero and
stopped (that was its end of life). Here the rule is explicit: nobody is paid as
a staker, the PoS tail is empty and the share stays with the proposer. The
chain therefore does not stop at 8425; it is exercised with real blocks across
8425 (`TestRW_RealChainPast8425AndSyncFromGenesis`, run with `NOSO_LONG=1`:
it builds 8430 blocks, which takes many minutes because every block is
fsynced; it was not completed in the final run, see the report), from genesis
in `TestRW_SyncFromGenesis` (260 blocks, three nodes) and, through a synthetic fast path, across
8425, 48010 and 88500 (`TestRW_BoundariesFastPath`). The fast path writes one
header-only block and credits a few accounts, then everything after it is real;
building 88500 real blocks is not feasible because the headers file is rehashed
for every block.

## Block 0

`BuildNewBlock(0, 1615132800, '', AdminHash, '')`: miner is the developer
address, start time 1531896783, header only, no trailer. The file is identical
on every node (tested). The genesis account is created first so that summary
slot 0 holds the last operation, which a restart reads back.

## Replaying and undo

`AddBlockToSummary`, `CompleteSummary` and `RebuildSummary` apply stored blocks
with the same state transition (V2 blocks) or the old rules (blocks without a
trailer, with the M-11 fix). A block that cannot be replayed is removed with
everything after it and the files restored; below the finality horizon this is
refused, the node is marked corrupt (`ErrCorrupt`) and stops replaying.
`RebuildSummary` restores the previous files and returns the error when a
block does not apply. `UndoLastBlock` restores the snapshot taken before the
last block and refuses to go below the horizon.

## Synchronisation

A node accepts blocks only through `AcceptBlocks`/`StageBlocks`: it verifies
and applies each block, so its summary, GVTs and locks are derived from verified
blocks and a node can start empty and take the chain from block 0. Summary
files are no longer requested on a vote. The vote-based requests for GVT and
lock files remain for compatibility, guarded by the full-hash vote; on a chain
born here they are redundant, since both are derived. A signed checkpoint
(starting from a recent state without replay) is not implemented.

## Things that are *not* validated

* The informational header fields `Difficult`, `TargetHash`, `Solution`,
  `NxtBlkDiff` (sealed by the proposer, no effect on state).
* Whether a masternode really runs: the proposer lists them from reports it
  challenged; followers check stake and shape only.
* Minimum fees (pool policy only), locks on staked funds at block level, and
  the frozen-address list.
