# Compatibility notes

Three lists: behaviour of the original that is kept on purpose, safety
improvements that do not change behaviour toward honest peers, and what could
not be verified. Code locations are marked with `// COMPAT:` and the Pascal
file and line.

## 1. Original behaviour that is preserved

These affect consensus, files or the wire, are not security findings and were
**not** changed. Items that a security finding replaced are in section 2.

| # | Behaviour | Pascal | Go |
|---|---|---|---|
| 1 | Addresses are derived from the Base64 *text* of the public key, and RIPEMD-160 runs over the hex *text* of the SHA-256 | `nosocrypto.pas:245-258` | `crypto.GetAddressFromPublicKey` |
| 2 | `B16ToB58` reads bytes as a signed big integer; negative values lose leading 0xFF bytes. Used by transfer hashes `tR...` | `nosocrypto.pas:591` | `crypto.bigFromSignedBytes` |
| 4 | Address validation needs a 2 character checksum; `B10ToB58` and `BMDecTo58` differ for a checksum sum of 0 | `nosocrypto.pas:337` | `crypto.IsValidHashAddress` |
| 9 | Dev payment order id is `"1" + TrfrID` (no hash). The miner is no longer the project funds address: it is the sealing proposer (`consensus.md`) | `mpblock.pas:53`, `masterpaskalform.pas:2039` | `createDevPaymentOrder`, `validate.go` |
| 12 | PoS/MN percentage steps use 88400 while the PoS end constant is 88500 | `nosogeneral.pas:299,315,322` | `consensus` |
| 13 | `GetSupply` is 0 from block 420000 in the original. Replaced by the real schedule (L-06); no consensus effect, `GetStackRequired` only uses supply below block 110000 | `nosogeneral.pas:213-223` | `consensus.GetSupply` |
| 14 | `ProtocolLine` advertises `0.4.4zzz`, `GetPTCEcn` `0.4.4Ab9` | `nosonetwork.pas:376,412` | `Engine.ProtocolLine` |
| 15 | `$LASTBLOCK` is answered with blocks n+1.. on the dispatcher path and n.. on the server path | `mpprotocol.pas:693`, `masterpaskalform.pas:2531` | `sendBlocks`, `handleLine` |
| 16 | `ValidProtocolCommands` is a substring test (an empty command passes) | `masterpaskalform.pas:2602` | `network.ValidProtocolCommands` |
| 20 | The `NSLORDER` text is also broadcast to all peers | `mpparser.pas:813-818` | `Engine.SendFunds` |
| 21 | Orders already mined are found only through the optional blocks database | `mpred.pas:893` | `Engine.OrderDetails` |
| 22 | `Trim(result)` calls whose value is discarded leave trailing blanks (`NSLPEND`, locked MNs) | `mpcoin.pas:454`, `nosopsos.pas:368` | `PendingRawInfo`, `PSOs.LockedRaw` |
| 23 | JSON: `/` escaped, non-ASCII as `\uXXXX`; wrong-shaped requests give an empty body | `fpjson`, `mprpc.pas` | `rpc/json.go`, `rpc.Parse` |
| 24 | `StrToInt`-family functions follow FPC 3.2.2 x86_64 `Val` exactly (`codec/val.go`): blanks and tabs skipped before an optional sign; base prefixes `$`, bare `x`/`X`, `0x`/`0X`, `&` (octal), `%` (binary); leading zeros stripped; a NUL ends the number successfully; trailing characters, an empty digit string and inputs longer than 255 bytes fail. Base 10 is range checked against 64 bits only, so `StrToInt`/`StrToIntDef` wrap to 32 bits without an error (`4294967301` gives 5, `2147483648` gives -2147483648). Other bases accept the full unsigned 64-bit range and reinterpret it as signed (`$FFFFFFFFFFFFFFFF` is -1; `$FFFFFFFF` is -1 for `StrToInt`). `StrToBool` also accepts numbers (non-zero is true) | FPC `sstrings.inc` InitVal / `fpc_Val_SInt_ShortStr`, `astrings.inc`, `sysstr.inc` | `codec.StrToInt64`, `StrToInt`, `StrToIntDef`, `TryStrToBool`; `TestValDerivedFromFPCSource` |
| 26 | ShortStrings truncate silently; bytes after a shortened string keep their old values. Kept for every record that is read and written back: summary, GVT, wallet, order, block header, `Resumen` (headers file) and masternode lock (with its 3 padding bytes) keep the raw record and `Encode` overlays the fields on it. `Order.AssignSender` reproduces the block builder, which assigns the address over the 88 character public key and so leaves the key tail in the `Sender` bytes of N.blk. Not reproducible: `AddLockedMM` leaves its new lock record uninitialised in Pascal, so tails and padding of new locks in psos.dat are stack garbage there and zero here | FPC; `mpblock.pas:199,212,227`, `nosopsos.pas:159-172,222,296,310-312` | `codec.PutShort`, `types` `raw` fields; `TestShortStringTailsPreservedEverywhere` |
| 27 | `GetMultiSource` can duplicate entries while sorting | `nosocrypto.pas:475` | `crypto.GetMultiSource` |

## 2. Security fixes (SECURITY_REVIEW.md)

The fix status of every finding is in the `Fix status` column of `SECURITY_REVIEW.md`; not every finding is closed, and rows without an entry there have not been
re-checked since the first fix round. Fixes override "preserve exactly"
because the network is inactive. Code carries `// FIX(<ID>):` comments with
the original Pascal location. "Breaks interop" means a Go node with the fix
and an unmodified Pascal node disagree on the wire, in a signed object or in
consensus; a Pascal node would reject or ignore what the Go node sends.

No fix embeds a key: the keys the original held (developer/admin key, config
key, seed and validator keys, release key) are options in `advopt.txt`
(`AdminKey`, `ConfigKey`, `ValidatorKeys`, `SeedKeys`, `ReleaseKey`) and
default to empty, meaning "nobody is trusted for that purpose". The only
remaining literal is the genesis block miner address, which is chain history
and not a trust anchor.

| ID | Fix | Breaks interop | Test |
|---|---|---|---|
| C-01 | `SETCFGDATA` only as an answer to our request, carries `seq sig content`, verified under `ConfigKey` over the full text; `NOSOPAY` execution removed from block building | yes | `TestC01_UnsolicitedAndUnsignedConfig` (network), `TestC01_NoSoPayAndSignedConfig` (node) |
| C-02 | `BLOCKZIP` only as an answer; decoded in memory; flat entries `^[0-9]+\.blk$`; entry/size caps; nothing extracted by path | yes (entry names) | `TestC02_H05_H06_UnsolicitedFilesRefused`, `TestC02_C03_StageBlocks` |
| C-03 | **Every block is verified by every node that stores it** (`docs/consensus.md`): proposer seal, parent hash, time slot, reward, each order's public key / address binding / signature / derived `TrfrID` / time window, balances, ownership of GVTs, aliases, project payment, masternode list (distinct, staked) and share (derived with checked arithmetic, must match exactly), order caps per type. A new block trailer carries the full public key of every order and the proposer seal; blocks without it stay readable but are refused from peers. State files (summary, GVT, PSO) are derived by applying the blocks, not downloaded on a vote; the remaining voted-file paths need the full 128-bit hash of more than half of ALL seeds. Replay failures roll the files back | yes (new block trailer; old blocks fail the TrfrID and parent-hash rules) | `TestRW_ForgedSpendRejected`, `TestRW_NoDowngradeNoStranger`, `TestRW_StateRulesEnforced`, `TestRW_MNShareChecked`, `TestRW_BuilderNeverExceedsValidator`, `TestRW_BoundariesFastPath`, `TestRW_SyncFromGenesis`, `TestRW_RealChainPast8425AndSyncFromGenesis` (`NOSO_LONG=1`), `TestC02_C03_StageBlocks` |
| C-04 | `TrfrID` derived from all signed fields and recomputed on receipt and in every received block; replay is closed by the order time window (an order is only valid in the block interval it was signed for, `prev.TimeStart <= t <= TimeEnd-60`) plus the id test against the previous block | yes | `TestC04_TrfrIDBoundAndReplay`, `TestRW_StateRulesEnforced` |
| C-05 | Amounts and fee range checked, sums with overflow checks, negative credits/debits refused in the summary | yes (rejects what wrapped in history) | `TestC05_Overflow`, `TestSummaryRefusesGarbageAddresses` |
| C-06 | `CUSTOM` fee must equal the exact custom fee, amount 0, valid unused alias; the debit equals the fee | yes | `TestC06_CustomFee` |
| C-07 | Validators registered per IP with their sign address (`ValidatorKeys`); check signed over block, validator and nodes under its own domain; each IP counted once per check. Independently of validators, every received masternode report is challenged: the IP must answer `MNVER <nonce>` with a signature of the report's sign key before the report is listed, so verification is on by default | yes | `TestMNChecksSecurity`, `TestC07_ReportNeedsAnsweringIP` |
| C-08 | `update`, `getbeta`, `checkupdates`, `sendreport`, `testnet` and the update/restart directives removed; nothing is downloaded or run | yes (directives ignored) | `TestC08_NoUpdateCommands`, `TestH02_DirectiveReplay` |
| H-01 | Reports carry the fund owner's key and signature, bound to the current block; funds and zero-validation checks apply to every report. Cold funds: a one-time delegation signed by the funds key (`SignDelegation`, `SetDelegation`) lets the sign key report, so the stake never has to be on the server | yes | `TestMNReportSecurity`, `TestRW_ColdFundsReport` |
| H-02 | Directive signature covers sequence, expiry height and a domain tag; sequence persisted (`directive.seq`) | yes | `TestH02_DirectiveReplay`, `TestH02_DirectiveOverTheWire` |
| H-03 | No built-in admin key; `AdminKey`/`ConfigKey` configurable; directives cannot move funds | yes | `TestC01_NoSoPayAndSignedConfig`, `TestH02_DirectiveReplay` |
| H-04 | More than half of all configured seeds must agree, one vote per host whatever its port; optional signed status per seed (`SeedKeys`, default empty: the status is only a hint, nothing is stored or deleted on it). The reorganisation limit is cumulative: at most 20 blocks below the highest tip ever reached (`highwater.seq`), also across restarts; a deeper request returns -1 and `CompleteSummary` stops with `ErrCorrupt` instead of retrying forever. Vote values are still 5-character prefixes (see notes) | partly (signed status suffix is ignored by old nodes) | `TestRW_ReorgLimitCumulative`, `TestRW_CorruptBelowHorizonStops`, `TestH04_ReorgDepth`, `TestH04_QuorumAndDedupe`, `TestH04_SignedStatus` |
| H-05 | `RESUMENFILE`/`HEADUPDATE` only as answers, voted full hash and local blocks checked before anything is written; a headers mismatch no longer wipes the pool | yes | `TestC02_H05_H06_UnsolicitedFilesRefused`, `TestH05_RequestedFileHashChecked` |
| H-06 | `MNFILE`/`PSOSFILE` only as answers with hash/size checks | yes | `TestC02_H05_H06_UnsolicitedFilesRefused`, `TestM09_PSOCountsChecked` |
| H-07 | Canonical signed encoding: tag, chain id, domain, length-prefixed fields including type and reference | yes | `TestCanonicalSignVerify`, `TestC04_TrfrIDBoundAndReplay` |
| H-08 | Raw bytes are hashed; the lenient Base64 decode of messages is gone | yes | `TestCanonicalSignVerify` |
| H-09 | Bearer tokens (read/spend), loopback bind, Origin and content-type checks, no private key in answers | yes (clients must send a token) | `TestH09_RPCAccessControl`, `TestH09_LoopbackBindAndHostFilter` |
| H-10 | Wallet in `wallet.enc` (Argon2id + AES-256-GCM, mode 0600). Migration of `wallet.pkw` never destroys anything: the records are sealed byte for byte, read back from disk, decrypted and compared with the original, and every key pair is checked (sign/verify and address); `wallet.pkw` and its `.bak` stay in place, and removing them is an explicit step (`RetireLegacyWallet`). A read-only open (status style commands) neither migrates nor creates nor saves. `-insecure-plain-wallet` wins over a passphrase, is never migrated, and is refused when a `wallet.enc` exists. A missing `wallet.enc` next to a `wallet.enc.bak` restores the backup or fails; it never starts a new wallet over it. Saves are serialised and `Add`/`NewAddress` write through before returning. Key commands never echoed or logged | no (local file) | `TestH10_WalletEncryptionAndMigration`, `TestWalletMigration*`, `TestWalletConcurrent*`, `TestWalletReadOnlyDoesNotMigrate`, `TestInsecurePlainWalletSemantics`, `TestH10_SensitiveCommands` |
| H-11 | Per-kind maximum sizes, no presizing, idle and whole-transfer deadlines, reads and file sends outside the heartbeat lock | no | `TestStreamLimits`, `TestStalledTransferDoesNotBlockTick` |
| M-01 | Receiver-side alias rules; only `TRFR`, `CUSTOM`, `SNDGVT` in orders; an alias is unique across blocks (the alias index is updated when an existing account gets an alias, `Summary.AliasTaken`) | yes | `TestC06_CustomFee`, `TestM01_OrderType`, `TestRW_AliasAcrossBlocks` |
| M-02 | Certificates verified (Go default); seed list used only over https with a detached signature under `ReleaseKey` | no | `TestM02_SignedSeedList` |
| M-03 | Median of up to five NTP servers, at least two answers, correction limited to 120 s | no | `TestM03_MedianOffset` |
| M-04 | Peer statements about our IP ignored; `GETMIIP` needs two agreeing nodes and `MNAutoIp` | no | `TestM04_PeerCannotSetMyIP` |
| M-05 | `MNVER <nonce>`: answer signed by the Sign key over nonce, state and funds | yes | `TestM05_MNVERChallenge` |
| M-06 | One state lock for the shared flags, mutexes elsewhere, panics contained per connection; `go test -race` | no | `TestM15_PanicContained` and the race run of every package |
| M-07 | 200 lines per 10 s per connection | no | `TestRateLimits` |
| M-08 | 10 costly one-shot requests per minute per peer | no | `TestRateLimits` |
| M-09 | File counts checked against the size before parsing | no | `TestM09_PSOCountsChecked`, `FuzzDecodeBlock`, `FuzzPSOParse` |
| M-10 | Blocks are sealed by authorised proposers (`proposers.txt`); a fork is settled by the heaviest valid branch (turn weight, ties by lower tip hash), not by a vote. A node never deletes a valid block unless a fully validated, preferred branch is in hand | yes | `TestM10_MinorityProposerKeepsItsBlocks`, `TestRW_ForkChoiceConverges`, `TestRW_WeightAndPreference` |
| M-11 | One state transition (`applyOrder`, `applyEnd`) is used by the builder, the validator and the replay, so build and replay agree byte for byte; unfunded transfers invalidate a block | yes | `TestRW_BuilderNeverExceedsValidator`, `TestBuildTransferBlockAndReplay` |
| M-12 | fsync + rename + directory sync; a build takes a state snapshot first and puts it back on any failure; pool and masternode tables are consumed only after success, so a retry cannot pay twice | no | `TestM12_AtomicWrite`, `TestM12_WriteFailureStopsBuild`, `TestRW_FailedWriteRetryPaysOnce` |
| M-13 | SHA-256 signatures with low-S, identities (`IDHash`) are 128 bits of SHA-256 instead of MD5 | yes | `TestLowSEnforced`, `TestIDHash` |
| M-14 | The GVT owner's key authorises a transfer; fee counted after the debit; ownership checked before the debit; the reference must be the canonical decimal 0..99 | yes | `TestM14_GVTOwner`, `TestRW_BuilderNeverExceedsValidator` |
| M-15 | Go bounds checks, fuzzed parsers, JSON shape checks | no | `FuzzParsersNoPanic`, `FuzzDecode`, `FuzzReadLine`, `FuzzParse`, `FuzzDispatch` |
| M-16 | Actions pinned to commit SHAs, `permissions: contents: read`, fixture checksums | no | `TestM16_FixtureChecksums` |
| L-01 | `M` addresses and over-long names refused as receivers. The sum checksum itself is kept because existing addresses depend on it; a new address version was not introduced (see notes) | yes | `TestL01_L08_Receivers` |
| L-02 | Only four-part public unicast IPv4 | yes | `TestIsValidIP` |
| L-03 | Unparsable orders are errors; first error code kept | yes | `TestL03_ResultsAtEntry` |
| L-04 | Per-peer file and request timers | no | `TestRateLimits` |
| L-05 | Certificates bind audience and a verifier nonce; XOR removed | yes | `TestCertificateAudienceAndNonce` |
| L-06 | Supply follows the halving schedule | yes (RPC/console values) | `TestSupply` |
| L-07 | Log text escaped, cut at 512 bytes, rate limited | no | `TestL07` |
| L-08 | Over-long fields rejected instead of truncated | yes | `TestSummaryRefusesGarbageAddresses`, `TestL01_L08_Receivers`, `TestParseOrder...` in `types_test.go` |

Notes on findings that are only partly addressed:

* **H-04**: votes remain 5-character prefixes (of 128-bit hashes). The quorum,
  de-duplication, depth limit and optional signed status close the attacks the
  review describes; full-length voting needs a longer status record.
* **L-01**: a stronger checksum needs a new address version and migration of
  every address; not done.
* **M-10**: this is a proof-of-authority design, see `docs/consensus.md`
  "Trust model". It does not stop an authorised proposer from censoring
  orders or from signing two blocks for one slot inside the 20-block window.
  There is no finality gadget; the proposer list is configuration that every
  node of a chain must hold identically (it is not committed to by block 0).
* **Checkpoints**: a signed checkpoint (fast start without replaying from
  block 0) is not implemented. A new node takes the chain from block 0.
* **H-10**: the plaintext `wallet.pkw` is kept after migration (a mistyped
  passphrase cannot lose keys). Until it is removed the keys also exist in
  clear text; `RetireLegacyWallet` overwrites with zeros and removes it after
  re-checking `wallet.enc`, which is best effort on journaling or flash
  storage. `expwallet` writes a true clear-text `.pkw` (mode 0600, the front
  end must show `storage.PKWExportWarning`).
* **M-13**: `blocks_db.nos` files written by the Pascal node index with MD5
  and are not found by `DBIndex` (SHA-256 based); the file has to be rebuilt.
* Replay credits masternode and PoS rewards as 64-bit values
  (`node/block.go`). The Pascal replay (`mpdisk.pas:709,721`) passes them
  through the 32-bit `StrToIntDef`, which on FPC 3.2.2 x86_64 wraps: block
  120000 with one masternode (2350000000) is credited as -1944967296 there
  and +2350000000 here. Only rewards above 21.47 NOSO per node are affected.
  The Go value is the intended one; this is a known divergence, not a fix.

## 3. Hardening (no change toward honest peers)

* Lines are limited to 4 MiB and files to 256 MiB; per-slot queues are bounded.
* Received header, summary and GVT files must be whole records; block zips
  are extracted by base name only (no path traversal) and limited in size.
* Files are written atomically (temporary file plus rename).
* Block files are parsed with bounds checks; truncated files return errors
  instead of crashing.
* Negative GVT numbers are rejected (Pascal would index outside the array).
* `PTC_Order` validation does not read past the parsed order array.
* `CreateNew` resets stale per-block records before crediting the premine.
* Entries that Pascal would index out of range (`GetVerificatorsText`) are
  clamped.
* The RPC request body is limited to 1 MiB.

## 4. What could not be verified

### FPC assumptions

Every "FPC does X" claim below was read from the FPC 3.2.2 sources
(`rtl/inc/sstrings.inc`, `astrings.inc`, `rtl/objpas/sysutils/sysstr.inc`,
`packages/fcl-base/src/base64.pp`, `rtl/objpas/classes/util.inc`) and the
bundled CryptoLib4Pascal; none was run. The Go behaviour depends on:

| Assumption | Where | Status |
|---|---|---|
| FPC 3.2.x on a 64-bit CPU (`ValSInt` is Int64); the RTL is built without range checks | `codec/val.go` | Not stated by the source tree. On other FPC versions or 32-bit targets `Val` limits by destination size and overflow fails |
| `Val` prefixes, NUL, 255 limit, wrap (item 24) | `codec/val.go` | Derived from source, tests in `val_test.go` |
| `Copy(s, 0, n)` is the first `n` characters | `codec.GetOpData` | Correct (`fpc_ansistr_copy`) |
| ShortString assignment leaves the old tail (item 26) | `types` | Correct in FPC |
| psos.dat lock record has 3 padding bytes | `types.MNLockSize` | By alignment rules; no real file to test |
| `DecodeStringBase64` in MIME mode (key/signature decoding) | `crypto/b64.go` | Reproduced from `base64.pp` including the `GetSize` rules: `QUJDQUI*` gives `ABC`. Unverified by a run; if the computed size is 0 `TStream.CopyFrom` may raise in FPC, here the result is empty |
| `HexToBin` stops at the first bad character, never raises; `-` is removed first | `crypto/basen.go` | Derived from `util.inc` and `ClpConverters.pas` |
| `UpperCase`/`StringReplace(rfIgnoreCase)` are ASCII only | `codec.ASCIIUpper`, `storage.replaceFold` | Correct for the non-wide-string manager; `strings.ToUpper` calls remain in `network`, `cli`, `rpc` and `node` |
| `TryStrToBool` reads a Double first | `codec.TryStrToBool` | Float syntax approximated (decimal digits, point, `E`) |
| Raw bytes equal FPC strings | all hashing | Only for valid UTF-8 input. `HashSha256String` converts through UnicodeString and UTF-8 (`HlpConverters.pas`); text with invalid UTF-8, such as a garbage `sender`, hashes differently in Pascal. Not reproduced |
| Reading a ShortString whose length byte exceeds its capacity | `codec.GetShort` | Pascal would read into the next field; Go clamps. Corrupt files only |
| `BMHexTo58("00")` | `crypto.BMHexTo58` | The Pascal result depends on `BMAdicion`'s output form and was not derived; unreachable from a real hash |
| `B16ToB58` signed reading, drops leading `FF` (item 2) | `crypto/basen.go` | Checked against `ClpBigInteger.pas` |
| Negative `Seek` raises | `storage/headers.go` | By source reading |

* **No interoperability test.** Free Pascal is not installed and the live
  network was out of scope. Nothing here has talked to a real Pascal node.
* Text encoding: strings are passed as raw bytes. This matches FPC on Linux
  with UTF-8; on Windows with other code pages the original may re-encode
  non-ASCII text.
* `PTC_SendGVT` returns an undefined value for unparsable input in Pascal;
  0 is returned here.
* `IsValidIP` rejects `127.0.x.x` and `192.168.x.x`, so masternode logic
  cannot be exercised on loopback or LAN addresses.
* Timing: thread scheduling differs; the goroutine heartbeat runs every
  200 ms like the original timer but ordering within a tick may differ.
* Golden files in `storage/golden_test.go` (N.blk, psos.dat, wallet.pkw,
  advopt.txt) are assembled by hand from the record declarations. They are
  DERIVED, not captured from a Pascal node.
* Downloaded state files are compared with the seeds' full-hash vote, not
  with the 5-character prefix of the original. The trust root is the majority
  of the configured seeds (optionally signed status, H-04); a majority of
  colluding seeds can still dictate state. State is not rebuilt from sealed
  blocks.

## 5. Things found in the real data

* 11 of the 4956 accounts of the real summary at block 59238 are garbage
  names (`androidx.lifecycle.MutableLiveData@...`, 40 characters), a direct
  consequence of nothing listed in section 1 (the origin was not analysed;
  the stale-tail rule of item 26 does not explain whole garbage names).
* The real summary contains neither `AdminHash` nor the project funds account
  at that height, consistent with the build path touching only the genesis
  account (fixed to be the only behaviour, M-11).
