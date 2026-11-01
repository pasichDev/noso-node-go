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
  1000 from 88400, capped at 6000. The mode field is not read: `MNSONLY` has
  no effect on a block (the original paid 9000 with it).
* PoS: 1000 for 8425..39999, then `1000 + ((block-39000) div 1000) * 100`
  capped at 2000, 0 from 88400 (never paid here, see below).
* Project: 1000 from block 88500 (`PoSBlockEnd`, where the derived project
  payment starts). The percentage steps use 88400 and the payment 88500, so
  blocks 88400..88499 pay nothing to the project; the miner keeps that share.
* The miner (here always the project funds address, see below) gets the rest.

All divisions truncate (Int64 `div`).

## Trust model

The chain is proof of authority. There is no mining.

* **Proposers.** `NOSODATA/proposers.txt` lists the public keys (one per line,
  in rank order) that may seal blocks. It is chain configuration: every node
  of a chain must hold the same list in the same order (`Node.SetProposers`).
  The list is fixed for the life of the chain (no rotation; a new list is a
  new chain). Every sealed block carries its digest in `Solution`, so a node
  with another list refuses block 1 at once, `SetProposers` refuses a different
  list once the chain has blocks, and at start `proposers.txt` must match the
  digest the chain commits to. An empty, unreadable, malformed, repeated-key or
  missing (on a chain with blocks) list is a hard error at start. A node with no
  list yet accepts nothing and builds nothing.
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
  an order, mint coins, or pay a masternode that is not staked: every follower
  checks all of it (below). It cannot make itself richer by the masternode
  list: the masternode pool of a block is reserved whatever list it publishes,
  and the unpaid part is burnt (`consensus.Shares`), so listing nobody earns the
  proposer nothing extra. Only the proposer knows which masternodes answered, so
  followers check the listed entries, not that the list is complete: a proposer
  can still leave a masternode out of its block (a censorship power, like
  leaving out an order), it just gains nothing by it.
* **What it can do.** Choose which pending orders to include (censor or
  reorder), and sign two different blocks for its slot. The second case is
  settled by the fork rule; until a heavier branch can no longer appear a payment
  can be reversed. Treat a payment as final after 20 blocks, not one.

## Fork choice (M-10, re2)

A valid block adds a score: its weight `k - rank` (`rank` = distance of its
proposer from the turn holder, `BlockWeight`) minus `k` for every slot skipped
since its parent (`BlockScore`). A branch from a common block is preferred
(`Preferred`) when its score is higher, then when its tip time is earlier, then
when its tip hash is lower. All inputs are facts of validated blocks, never
votes, and nothing depends on the node's own history: **there is no local
finality in the decision**. A node that sees the same blocks ends on the same
chain whatever tip it had, so two nodes one block apart cannot be split for good.
Consequences:

* A proposer cannot orphan the block before it by building on the same parent
  in the next slot: the skipped slot costs a block, and at equal score the
  earlier tip wins. The header is pinned (below), so the only freedom left to
  grind a hash is the choice of orders in a block for a slot the proposer owns,
  which is equivocation. Equivocation evidence is not recorded (not
  implemented).
* A fork of any depth is resolved. Snapshots (`UNDO/N`, last 32 blocks) make a
  shallow switch cheap; if there is none, the node replays its own blocks up to
  the fork (`rebuildLocked`), which is slow but needs no one's word. The sync
  layer asks for blocks `BlocksRequestFrom` (the tip normally; 20 blocks
  earlier, then 40, 80, ... each time the answer does not link, up to genesis).
  A branch that is not yet heavier than ours is kept in memory (at most 20000
  blocks) and `BlocksRequestFrom` asks for the blocks after it, so a long
  branch is compared as a whole, not window by window.
* The price is that a key holder who can build a heavier branch can rewrite
  history of any depth. That is the trust model of a proposer chain (the list is
  the authority); `Finalized()` and the highest-tip file `highwater.seq`
  remain only as guards for the operator commands `undoblock` and
  `removeblocks`, not for fork choice. Nodes run by exchanges should wait for
  confirmations, and monitor `Adopted a heavier branch` in the log.
* Blocks are checked in two steps: seal, link and score first (nothing is
  touched), then the state. A branch that cannot win costs signature checks, not
  state copies.

The seeds' vote (`NODESTATUS`) only tells a node where to look.

## Commit, crash safety and the state root

Every sealed block carries, in the `Solution` header field, `NSR1 <state root>
<proposer digest>`. The state root is the SHA-256 of the three consensus state
files (summary, GVT, locks) after the block was applied. `TargetHash` equals the
parent hash, `Difficult`, `TimeLast20` are 0 and `NxtBlkDiff` is the masternode
count from block 53000; nothing else in the header is free. A follower refuses a
block whose state root differs from the state it computes, so a divergence is
seen by every node at that block; a replay checks each block's root too.

A change of the chain (a built block, an accepted run, a reorganisation) goes
through a journal (`commit.go`): durable snapshot of the starting state, stage-1
journal, apply to the state files, stage-2 journal with the raw blocks (the
commit point), write blocks and header records, remove the journal. Recovery at
start restores the snapshot and either drops the change or runs the journalled
blocks through the normal acceptance code. It then checks `LastOp`, the headers
file and the tip's state root against the live state and replays the chain when
they differ. A block delivered again after a crash therefore meets a state that
has not applied it. A write failure after the commit point is recovered at once
from the journal; if that fails the node is marked corrupt and stops until
restarted. Blocks and state files are written with fsync (a test-only option
`storage.SetNoSyncForTests` skips it so a test can build thousands of blocks).
Blocks made by builds before this change carry no state root and cannot be
replayed; recreate such a test chain.

## Block format

`N.blk` is the original layout (header, 562-byte orders, PoS tail from 8425,
masternode tail from 48010) followed by a trailer: `"NSG2"`, the count and the
full public key of every order (empty for the project payment), then the
proposer key and signature. The block hash is the hash of the whole file, so it
covers the signature, and the signature text is canonical (strict Base64, low-S
DER; `crypto.VerifyCanonical`): a block re-encoded by a third party is refused
and no one can change a block's hash without the key (`TestRE2_ReencodedBlockRefused`). Block 0 has no trailer. Blocks without a trailer
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
masternode pay equals `share / count` exactly, the header fields above, a plain
`Reference` (letters, digits and `_-.,@+*=#/!?%&[]{}~^|<>`, at most 64 bytes),
and for `TRFR` lines: lines with one `OrderID` form a complete group numbered
1..n that pays one receiver at one time, with an id derived from its lines.

Stateful (`applyBlockState`, the same functions the builder uses): `TRFR`
needs the funds; `CUSTOM` the funds and a free alias; `SNDGVT` ownership and the
fee; masternodes are distinct, valid and hold the stake. Any failure puts the
files back and refuses the block. Shares use `consensus.Shares` with 128-bit
intermediate products and do not read the local `CFG` mode (`MNSONLY` is
ignored). The order selection of the builder and the check of the follower use
the same functions, and a test builds 2000 `TRFR` plus 3 `SNDGVT` at heights 100
and 88499 and applies them on a second node. This is a tested property, not a
guarantee: the masternode list is built from the stake at the height of the
block being built (it was one block earlier, which refused an honest block
exactly at the stake), and a multi-line order is taken whole or not at all.

## Building a block (`Node.BuildNewBlock`)

Everything is under the chain lock, shared with block acceptance and with the
console commands `undoblock`, `rebuildsum` and `completesum`.

1. Skip when `SkipBlocks`; in mode `STOP` clear the pool and skip; in mode
   containing `EMPTY` clear the pool and continue.
2. The timestamp must be a slot boundary after the last block's end and not
   more than 5 s in the future; the wallet must hold a proposer key.
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
chain therefore does not stop at 8425. `TestRE2_ChainAcrossBoundary` builds a
real chain from genesis to 8428 (without `-short`), syncs a second node through
the archive path, restarts it and replays it from genesis with every state root
checked. `TestRW_SyncFromGenesis` does 260 blocks with three nodes, and a
synthetic fast path covers 8425, 48010 and 88500 (`TestRW_BoundariesFastPath`:
one header-only block, then everything after it real). Building 48010 and 88500
real blocks is not done.

## Block 0

`BuildNewBlock(0, 1615132800, '', AdminHash, '')`: miner is the developer
address, start time 1531896783, header only, no trailer. The file is identical
on every node (tested). The genesis account is created first so that summary
slot 0 holds the last operation, which a restart reads back.

## Replaying and undo

`AddBlockToSummary`, `CompleteSummary` and `RebuildSummary` apply stored blocks
with the same state transition (V2 blocks; every block is committed before the
next is applied, as in forward validation, and its state root is checked) or the
old rules (blocks without a trailer, with the M-11 fix; known gaps: the
legacy replay does not touch masternode locks, and a peer's block without a
trailer is refused, so a migrated chain can only be copied as a data directory,
not synchronised from genesis). A block that cannot be replayed is removed with
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
