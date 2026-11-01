# Storage

All files live in `NOSODATA/` (configurable). Integers are little-endian.
A Pascal `String[N]` is `1 + N` bytes: a length byte, then up to `N`
characters; unused bytes after the length are left as they were (zero for new
records). Records are `packed` (no padding) unless noted.

| File | Content |
|---|---|
| `sumary.psk` | account summary: 106 byte records |
| `sumary.zip` | zip of the summary, entry `data/sumary.psk` (rewritten after each block) |
| `blchhead.nos` | headers: 70 byte records, record index = block number |
| `BLOCKS/N.blk` | block N |
| `BLOCKS/DB/blocks_db.nos` | optional order index: 16 byte records |
| `gvts.psk` | 100 GVT records of 105 bytes |
| `nosocfg.psk` | one line of text (see below) |
| `masternodes.txt` | one line `BLOCK ip;port:fund:age ...` terminated with CR LF |
| `wallet.pkw` | wallet: 626 byte records |
| `psos.dat` | PSO file |
| `advopt.txt` | text options |
| `*.bak` | copies of summary, wallet and GVT files taken before changes |

## Summary record (106 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 41 | `Hash` String[40], the address |
| 41 | 41 | `Custom` String[40], the alias |
| 82 | 8 | `Balance` int64 |
| 90 | 8 | `Score` int64 |
| 98 | 8 | `LastOP` int64 |

Record 0 is the genesis account; its `LastOP` is the last block. Verified
against the real 59238 summary (4956 accounts, round trip byte exact). It
contains 11 accounts whose "address" is the text
`androidx.lifecycle.MutableLiveData@xxxxx`: receivers are never validated, so
a transfer to garbage creates an account named with the first 40 characters
of the garbage.

## Header record (70 bytes)

`block` int32 at 0; `blockhash` String[32] at 4; `SumHash` String[32] at 37.

## Block file

```
BlockHeader (368)
Order * TrxTotales (562 each)
if number >= 8425:  int64 posReward, int32 posCount, posCount * String[32] (33 bytes)
if number >= 48010: int64 mnReward,  int32 mnCount,  mnCount * String[32] (33 bytes)
```

Header: `Number` int64 @0, `TimeStart` int64 @8, `TimeEnd` int64 @16,
`TimeTotal` int32 @24, `TimeLast20` int32 @28, `TrxTotales` int32 @32,
`Difficult` int32 @36, `TargetHash` String[32] @40, `Solution` String[200]
@73, `LastBlockHash` String[32] @274, `NxtBlkDiff` int32 @307, `AccountMiner`
String[40] @311, `MinerFee` int64 @352, `Reward` int64 @360.

Order (562): `Block` int32 @0, `OrderID` String[64] @4, `OrderLines` int32 @69,
`OrderType` String[6] @73, `TimeStamp` int64 @80, `Reference` String[64] @88,
`TrxLine` int32 @153, `Sender` String[120] @157, `Address` String[40] @278,
`Receiver` String[40] @319, `AmmountFee` int64 @360, `AmmountTrf` int64 @368,
`Signature` String[120] @376, `TrfrID` String[64] @497.

The block hash everyone compares is the MD5 of the whole file. Block 0 is
deterministic: a header only, no tails (see consensus).

## GVT record (105 bytes)

`number` String[2] @0, `owner` String[32] @3, `Hash` String[64] @36,
`control` int32 @101. 100 records in the real file (verified).

## Wallet record (626 bytes)

`Hash` String[40] @0, `Custom` String[40] @41, `PublicKey` String[255] @82,
`PrivateKey` String[255] @338, `Balance`, `Pending`, `Score`, `LastOP` int64
@594, 602, 610, 618. Keys are Base64 text. In `wallet.pkw` (the original
format, used only with `-insecure-plain-wallet` or for export) **the private
keys are stored in clear text**; the default file `wallet.enc` holds the same
records encrypted (see below).

## nosocfg.psk

Blank separated fields, each a `:` separated list:
0 mode (`NORMAL`, `STOP`, `EMPTY`, `MNSONLY` substring tests), 1 seed nodes
`ip;port:`, 2 NTP servers, 3 and 4 deprecated, 5 frozen addresses, 6 pending
project payments (`block,source,target,amount:`). The node edits it with the
`Add/Remove/Set` routines, which stop at the first empty field.

## psos.dat

`int32 block, int32 lockedCount, int32 psoCount`, then `lockedCount` x 40 byte
records (`String[32]` + 3 padding bytes + int32 expire block; unpacked record),
then PSO entries: `uint16 mode`, `string hash`, `string owner`, `int32 expire`
(a DWord in the record, read as Integer like the original),
`string members`, `string params`, where `string` is a `uint16` length plus
bytes. A masternode that is paid is locked for 2016 blocks.

## advopt.txt

`Key value` lines (see `storage/options.go`): HideEmpty, MultiSend, Language,
NoGUI, PoUpdate, Closestart, SendReport, BlocksDB, PRestart, SkipBlocks,
FormState, Autoserver, Autoupdate, WO_FullNode, MNIP, MNPort, MNFunds,
MNSign, MNAutoIp, RPCPort, RPCPass, RPCFilter, RPCWhiteList, RPCAuto,
RPCSaveNew, RPCBanned, MaxPeers, PosWarning. Lines starting with `//` and
`---` are comments. Booleans are `True`/`False`.

## Atomicity, locking, permissions

* `WriteFileAtomic` (temporary file, fsync, rename, directory fsync, mode
  0600) is used for every state file, including `advopt.txt`; a failed rename
  removes the temporary file. The resulting bytes are identical to the Pascal
  files. Appends to `blchhead.nos` and `blocks_db.nos` are written at the
  record boundary and synced, so a torn tail is overwritten (and cut when
  `blocks_db.nos` is opened). `.bak` copies are atomic too.
* `LockDataDir(root)` takes an exclusive flock (Windows: LockFileEx) on
  `root/.lock` and returns `ErrDataDirLocked` to a second holder. Every writer
  holds it for its whole life (nosod, the GUI, and nosocli when it opens the
  directory itself). After locking it runs `RecoverDataDir`: finishes or
  discards an interrupted `Txn` and removes `*.tmp` / `*.new` debris
  (wallet temporaries are overwritten first).
* `Txn` (`NewTxn(root)`, `Add(path, data)`, `Commit()`) replaces several whole
  files atomically: files are staged as `<path>.new`, a checksummed manifest
  `commit.journal` is written atomically (the commit point), the files are
  renamed, the manifest removed. A crash leaves all old or all new files.
  Whole-file only; one transaction at a time; `ErrTxnPending` means the
  journal is durable and restart completes it. Intended for the block file +
  headers + small state files; the in-place summary is not covered.
* The data directory is created and kept 0700, wallet files and `advopt.txt`
  0600 (existing 0644 files are tightened when opened or saved). Windows: modes
  and `os.Chmod` do nothing there. The directory inherits the ACL of its parent;
  keep it under the user's profile or run `icacls <dir> /inheritance:r /grant:r
  "%USERNAME%:(OI)(CI)F"`. No DACL is set by the node.

## Differences (security fixes)

* `wallet.enc` replaces `wallet.pkw`: `NOSOWLT1`, Argon2id parameters, salt,
  nonce, then AES-256-GCM over the same 626-byte records (header as
  associated data), mode 0600. An existing `wallet.pkw` is migrated on the
  first start with a passphrase and is **kept**: the migration is verified by
  a full read-back and key check, and nothing is deleted automatically (a
  mistyped passphrase must not cost the keys; to redo it, move `wallet.enc`
  away). Read-only commands never migrate. `-insecure-plain-wallet` uses the
  original format only, ignores a passphrase, and is refused while a
  `wallet.enc` exists. `expwallet` writes a true clear-text `.pkw`.
* New small files: `cfg.seq`, `directive.seq` (last accepted sequence numbers)
  and `nosocfg.sig` (the signature of the current configuration).
* File hashes shown in pings and statuses are `IDHash` values (see crypto).
* New `advopt.txt` keys: `AdminKey`, `ConfigKey`, `ValidatorKeys`, `SeedKeys`,
  `ReleaseKey`, `BuildBlocks`, `RPCToken`, `RPCSpendToken`, `RPCBind`,
  `RPCExposeKeys`.
