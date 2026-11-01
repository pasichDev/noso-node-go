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
* The miner (the sealing proposer, see below) gets the rest: whatever part of
  the masternode pool is not paid to a listed masternode (all of it when none is
  listed, plus the division remainder) is added to the miner's share, as in the
  original (`mpblock.pas:352`). Nothing is burnt: the coins in existence equal
  `GetSupply`.

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
  Honest nodes build only in their turn (`Node.InTurn`). A block of a proposer
  that does not hold the slot is refused until `OutOfTurnGrace` (120 s) after the
  slot's boundary, so nobody can seal another proposer's slot ahead of time and
  leave its holder unable to build; after the grace a missed slot can be filled
  by a stand-in, and the holder's own block, if it turns up, outweighs it.
* **Seal.** A proposer signs the whole block (header, orders, tails and the
  public keys of the orders) under the domain `BLOCKSEAL1`. The miner of the
  block must be the proposer's own address: block rewards are paid to
  proposers, which is also what puts spendable coins into a fresh chain (the
  premine sits on `AdminHash`, whose key nobody holds).
* **What a proposer cannot do.** Spend an account whose key it lacks, repeat
  an order, execute part of a multi-line order, mint coins, or pay a masternode
  that is not staked: every follower checks all of it (below).
* **What any proposer can do.** The proposers are fully trusted; the chain is
  exactly as honest as its proposer list. In particular a single proposer can:
  * **censor**: leave out any order, any masternode, any user, for as long as
    it likes (and an order a proposer leaves out waits for the next block of
    another proposer);
  * **rewrite history at any depth**: it signs blocks for the slots from an old
    fork point on, announces the tip, and every node adopts it, because fork
    choice is by score and has no finality (`Fork choice` below). A payment
    that was in the chain for any number of blocks can disappear, and with it
    the goods someone gave for it. There is **no point after which a block is
    final**; waiting for confirmations lowers the chance of an accident, not
    the power of a proposer. This is a limit of the trust model that is accepted
    and documented here, not a bug (finding F-1 of the final security audit);
  * **keep the masternode pool**: it publishes the masternode list; followers
    check that the listed entries are staked and distinct, not that the list is
    complete, and a proposer that lists only itself earns the same as one that
    lists nobody, because whatever the list does not pay stays with the miner.
    Nothing can be gained from the list beyond what the proposer already holds,
    and nothing in this design stops it from being used for censorship;
  * **choose and reorder orders**, and sign two different blocks for its slot
    (equivocation is not recorded).

  Run a chain only with proposers that its users trust together, and treat the
  proposer list as the root of trust of the chain.

## Fork choice (M-10, re2)

A valid block adds a score: its weight `k - rank` (`rank` = distance of its
proposer from the turn holder, `BlockWeight`) minus `k` for every slot skipped
since its parent (`BlockScore`). A branch from a common block is preferred
(`Preferred`) when its score is higher, then when its tip time is earlier, then
when its tip hash is lower. All inputs are facts of validated blocks, never
votes, and nothing depends on the node's own history: **there is no local
finality in the decision**. Consequences:

* A proposer cannot orphan the block before it by building on the same parent
  in the next slot: the skipped slot costs a block, and at equal score the
  earlier tip wins. The header is pinned (below), so the only freedom left to
  grind a hash is the choice of orders (and the random nonce of the signature)
  in a block for a slot the proposer owns, which is equivocation. Equivocation
  evidence is not recorded (not implemented).
* **A proposer can rewrite history of any depth** (see the trust model): a
  heavier branch from any old block is adopted, however many blocks follow it.
  Nothing is final and this document does not offer a number of blocks after
  which a payment is safe. `Finalized()` and the highest-tip file `highwater.seq`
  remain only as guards for the operator commands `undoblock` and
  `removeblocks`, not for fork choice. Monitor `Adopted a heavier branch` in the
  log.
* Nodes that are given the same blocks end on the same chain, but not
  necessarily at once: a run is judged as delivered, so the order and the
  grouping of the deliveries can leave two nodes on different tips until the
  next pull (a later request for the blocks above the fork delivers the rest).
  It heals through synchronisation; it is not a guarantee of instant agreement.
* Deep forks are looked for, not assumed away. Snapshots (`UNDO/N`, last 32
  blocks) make a shallow switch cheap; if there is none, the node replays its
  own blocks up to the fork (`rebuildLocked`), which is slow but needs no one's
  word. The sync layer asks for blocks `BlocksRequestFrom`: the tip normally;
  while a fork is suspected, 20 blocks earlier, then 40, 80, ... each time the
  answer does not link, up to genesis. When an answer links but holds only
  blocks we have, the fork lies after it and the next request continues from the
  end of that window (`probeResume`), so no stretch between two windows is
  skipped. Each window is verified once.
* A branch that is not yet heavier than ours is kept in memory, verified, and
  `BlocksRequestFrom` asks for the blocks after it, so a long branch is
  compared as a whole, not window by window. The staged branch is bounded: at
  most 20000 blocks and 256 MiB (`maxStaged`, `maxStagedBytes`); the blocks of
  a stage are refused before they are kept if they are from the future, off the
  slot grid, unsealed or not linked. A window that does not continue the staged
  branch (its first block does not name the staged tip as parent) drops the
  stage and is judged on its own. A branch over the bound is refused with an
  error and the stage released.
* Blocks are checked in two steps: seal, link and score first (nothing is
  touched), then the state. A branch that cannot win costs signature checks, not
  state copies; once it is staged, those checks are not repeated.

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
blocks through the normal acceptance code, without rewriting the journal it runs
from (a second crash finds the same journal). The undo data of the new blocks is
put in place before the journal is dropped, and the undo data of an abandoned
branch is removed once the change is committed, so a crash can never leave an
`UNDO/N` of the wrong branch. Recovery then checks `LastOp`, the headers file,
that the tip file is the block the headers recorded, and the tip's state root
against the live state, and replays the chain when they differ; the blocks
database is brought in line with the chain. A block delivered again after a crash therefore meets a state that
has not applied it. A write failure after the commit point is recovered at once
from the journal; if that fails the node is marked corrupt and stops until
restarted. Blocks and state files are written with fsync (a test-only option
`storage.SetNoSyncForTests` skips it so a test can build thousands of blocks).
Blocks made by builds before the state root existed carry none and cannot be
replayed; nor can a chain whose block 1 was sealed before block 1 created the
100 GVT records (`Block 0`, below). Recreate such a test chain.

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
`TimeEnd` a multiple of 600 not in the future, trailer and seal, a block of
another proposer's slot only after `OutOfTurnGrace`, miner is the proposer, reward, no PoS payment, per order: type, amounts in range, the
order time inside `[prev.TimeStart, TimeEnd-60]`, key belongs to the address,
signature over every field, `TrfrID` derived, receiver/alias/GVT shape, no
repeated id (also against the previous block), caps (2000 `TRFR`+`CUSTOM`, 100
`SNDGVT`, the derived project payment last from block 88500), fee total, the
masternode pay equals `share / count` exactly, the header fields above, a plain
`Reference` (letters, digits and `_-.,@+*=#/!?%&[]{}~^|<>`, at most 64 bytes),
and for `TRFR` lines: lines with one `OrderID` form a complete group numbered
1..n that pays one receiver at one time, with an id derived from its lines.
The line count `n` is part of every line's signature, so a proposer cannot
execute the first line of a two-line order as an order of one line
(`TestFinal_PrefixOfMultiLineOrderRefused`). A third party can still combine a
line it has seen with a line of its own into another group with the same line
count; that costs the signer of the seen line nothing it had not agreed to pay,
and the proposers are trusted with the choice of orders anyway.

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
   included) and applied. A wire order is taken whole or left whole; the pool
   only holds complete groups (`AddPoolGroup` checks line count, numbering,
   time, receiver, reference and derived id before any line is stored), and a
   malformed group found anyway costs only the line at hand, never the lines
   behind it. Skipped: older than the last block start, already in the last
   block, younger than 60 s before the block time, or past the caps (young ones
   stay in the pool).
5. Masternode list: reported nodes with enough validations that are valid,
   distinct and hold the stake at that height.
6. Closing payments (`applyEnd`): project share from 88500, masternode shares
   (each locked for 2016 blocks), the proposer gets the rest, the genesis
   account receives 0 so its `LastOP` is the block number.
7. Header, block file, headers record, orders index. On any failure the files
   are restored and the pool and masternode tables are left as they were.

The pool follows the chain on every node, builder or not: each accepted or
built block removes the orders it holds and every order too old for the next
block (`pruneMined`), and the pool holds at most `MaxPoolLines` (6000) lines. A
full pool refuses a new order; it never evicts an admitted one. That removes
free censorship, not paid censorship: a user with funds can fill the pool with
valid orders dated at the start of a period; about 2000 are mined (their fees go
to the proposer) and the rest are dropped unpaid at the next block, so honest
orders are delayed for a period at a small price. There is no fee market. Reorganised
away orders are not put back; a sender whose order vanished with an abandoned
block sends it again.

## Order lookup

`blocks_db.nos` indexes the orders of every block when the block is committed
(`indexBlock`; one write per block) and drops the records of a block when it is
removed or reorganised away (`dbRollback`); at start the database is brought in
line with the chain (`syncBlocksDB`). `OrderBlock` and `MinedOrder` read it.
The `BlocksDB` option no longer switches the index: it is always kept.

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
on every node (tested): `genesisBlock` is a function of the constants. The
genesis account is created first so that summary slot 0 holds the last
operation, which a restart reads back, and the premine goes to `AdminHash`.

**GVTs.** The genesis holds none. Block 1 creates the 100 GVT records
(`GVTs.Seed`, in `applyEnd`): numbers `0`..`99` (the canonical decimal the block
rules read), owner the proposer that seals block 1, a fixed hash per number. The
builder, every follower and every replay apply the same rule, so a rebuild
keeps them and the state root of block 1 commits to them. They are that
proposer's to distribute with `sendgvt`. They are not created for `AdminHash`,
because no key is known for it and a GVT nobody can sign for could never move.

**Atomic creation.** Block 0 and the state that comes with it (summary, locks,
headers) are several files and cannot change in one step. While the
chain has no block 1, every start therefore clears whatever an earlier run
left and writes genesis again, ending with the headers record: at any crash
point the next start ends with the genesis every honest node has, or with an
error (`TestFinal_CrashDuringGenesisEveryPoint`, every crash point,
`TestFinal_DoubleCrashDuringGenesis`). A block 0 that is not this chain's own
(data of another source) is left alone.

## Replaying and undo

`AddBlockToSummary`, `CompleteSummary` and `RebuildSummary` apply stored blocks
with the same state transition (V2 blocks; every block is committed before the
next is applied, as in forward validation, and its state root is checked) or the
old rules (blocks without a trailer, with the M-11 fix; known gaps: the
legacy replay does not touch masternode locks, and a peer's block without a
trailer is refused, so a migrated chain can only be copied as a data directory,
not synchronised from genesis). A block that cannot be replayed is removed with
everything after it and the files restored; below the finality horizon this is
refused (the guard is 20 blocks below the highest tip this node reached), the
node is marked corrupt (`ErrCorrupt`) and stops replaying. A chain born here
whose block no longer decodes as a sealed block is a replay failure, never
replayed by the lenient rules of the old network; and a start finds a tip file
that is not the block the headers file recorded.
`RebuildSummary` restores the previous files and returns the error when a
block does not apply. `UndoLastBlock` restores the snapshot taken before the
last block and refuses to go below the horizon.

## Synchronisation

A node accepts blocks only through `AcceptBlocks`/`StageBlocks`: it verifies
and applies each block, so its summary, GVTs and locks are derived from verified
blocks and a node can start empty and take the chain from block 0. Summary,
headers, GVT and lock files are never requested, and a peer that pushes one is
cut off. A signed checkpoint (starting from a recent state without replay) is
not implemented.

## Things that are *not* validated

* The informational header fields `Difficult`, `TargetHash`, `Solution`,
  `NxtBlkDiff` (sealed by the proposer, no effect on state).
* Whether a masternode really runs: the proposer lists them from reports it
  challenged; followers check stake and shape only.
* Minimum fees (pool policy only), the lock on the staked funds of a
  masternode at block level (`applyOrder` does not enforce it), `EMPTY`/`STOP`
  and the frozen-address list: a proposer can include orders the pool would
  refuse.
* `NOSOPAY` entries of the configuration are not executed.
