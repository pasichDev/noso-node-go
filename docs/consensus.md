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
| Developer key | `AdminPubKey` in `internal/consensus/rules.go` | |

Reward at the boundaries (tests in `internal/consensus/rules_test.go`):
block 0 = 1030390730000, 1..209999 = 5000000000, 210000 = 2500000000,
420000 = 1250000000, and the last paid period (blocks 2100000..2309999)
yields `5000000000 div 1024 = 4882812` (truncated). Block 2310000 and above
pay 0. The supply function (`GetSupply`) returns 0 from block 420000, as in
the original.

## Percentages (basis points of reward + fees)

* Masternodes: from 48010, `2000 + ((block-48010) div 4000) * 100`, plus
  1000 from 88400, capped at 6000; `MNSONLY` in the mode field gives 9000.
* PoS: 1000 for 8425..39999, then `1000 + ((block-39000) div 1000) * 100`
  capped at 2000, 0 from 88400.
* Project: 1000 from 88400.
* The miner (here always the project funds address, see below) gets the rest.

All divisions truncate (Int64 `div`).

## Building a block (`Node.BuildNewBlock`)

1. Skip when `SkipBlocks`; in mode `STOP` clear the pool and skip; in mode
   containing `EMPTY` clear the pool and continue.
2. The timestamp must not be before the last block's end nor more than 5 s in
   the future.
3. Backups of the summary and GVT file are taken.
4. Pending orders, in pool order, are processed. Skipped: older than the last
   block start, already in the last block, younger than 60 s before the
   block time or past 2000 transfers (those are kept for later). `CUSTOM`
   orders charge the literal 25000 and set the alias; `TRFR` orders must have
   the funds in the summary; `SNDGVT` orders are accepted only from the
   developer key.
5. Pending project payments from nosocfg field 6.
6. From block 88500 a `PROJCT` order pays the project 10 percent.
7. PoS: no addresses are ever paid. For blocks 8425..88499 the original divides
   by zero (the list is empty), which is reproduced as an error.
8. Masternodes: validation counts are credited, the list of paid
   masternodes (those with at least `(checks div 2) - 1` validations, which is
   *every* node when there are no checks) is written to `masternodes.txt`, and
   each receives the reward; each is locked for 2016 blocks.
9. The miner receives reward + fees minus the other shares, and the genesis
   account receives 0 so its `LastOP` becomes the block number.
10. Header, file, zip of the summary, headers record, ping.

The node always builds with miner `NpryectdevepmentfundsGE` and solution
`!!!!!!!!!100000000`: there is no mining in 0.4.4.

## Block 0

`BuildNewBlock(0, 1615132800, '', AdminHash, '')`: miner is the developer
address, start time 1531896783, header only. The file is identical on every
node (tested).

## Replaying blocks (`Node.AddBlockToSummary`)

Used when blocks were downloaded: the miner is credited reward + fees;
`CUSTOM` sets the alias (forced); `SNDGVT` pays the custom fee and changes
the owner; `TRFR` moves funds (if the sender cannot pay, the miner pays the
fee); `PROJCT` credits the project and debits the miner; PoS and masternode
shares are credited and debited from the miner. COMPAT: this path touches
`AdminHash` instead of the genesis account, so a replayed summary differs
from one built live. A node that replays and then finds a different summary
hash downloads the summary from a peer (this is what the loopback test
exercises).

## Undo

`UndoLastBlock` restores `sumary.psk.bak` and `gvts.psk.bak`, removes the
last header record and block file and re-reads the state. It refuses to go
below a block it already undid.

## Things that are *not* validated

Blocks received from peers are not verified at all: trust comes from the
network consensus on hashes. Receivers of transfers are never validated (see
the garbage accounts in the real summary).
