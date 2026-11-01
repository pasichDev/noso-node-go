# NosoNode security review

> **The network is inactive and this document is public.** The findings describe the original Free Pascal node; the Go port in this repository addresses them, but not every finding is closed: see the Fix status column below, the "Final audit" section after it, and `docs/compatibility.md`.

| | |
|---|---|
| Date | 2026-10-31 |
| Code reviewed | Pascal source tree (not part of this repository), HEAD `e0c9d87`, origin set to `nosocoin/NosoNode`, node version `0.4.4Ab9`. Equivalence with upstream was not verified. |
| Purpose | Defensive review, requested by the owner |

The repository README describes the project as archived, while this review was requested for a live network. Findings are written for the live case. If the network really is inactive, the severity of live-network impact falls, but the Go rewrite notes still apply.

## Executive summary

The review found **8 critical, 11 high, 16 medium and 8 low** issues. The critical items are not isolated mistakes. They come from five design gaps:

1. **Nothing validates a block.** The chain is not secured by proof of work or by block signatures. Every node builds each block locally, and a block is "correct" if its hash wins a plurality vote among about nine seed nodes. Downloaded blocks and summaries are checked only against a 5-character MD5 prefix, which is 20 bits (C-03, H-04).
2. **Nodes accept state they did not ask for.** Peers can push block archives, headers, configuration, masternode lists and lock tables without a request (C-01, C-02, H-05, H-06). The block archive is extracted into the node's working directory, so a peer can overwrite the wallet file.
3. **Signatures do not bind what they should.** Transfers can be replayed, because the transfer ID is not derived from the signed data (C-04). Fee, reference and type are unsigned (C-06, H-07). Masternode checks are signed by any key at all (C-07).
4. **Amounts are not range-checked.** `amount + fee` overflows in release builds and mints coins (C-05). A `CUSTOM` order's fee is taken from the wire and paid out without being charged (C-06).
5. **Updates are unsigned, and auto-update is on by default.** A release zip is executed with no hash or signature check (C-08). Old admin directives can be replayed at any time (H-02).

The highest-impact single items are:

- **C-01:** any peer can install a forged network configuration, including unsigned transfers out of any address.
- **C-02:** any peer can overwrite files in the node directory, including `wallet.pkw`.
- **C-04:** anyone can replay a signed transfer until the sender's balance is gone.
- **C-05 and C-06:** unlimited coin creation.
- **C-08:** unsigned auto-update gives fleet-wide code execution to anyone who controls the release channel.

**Suggested order of work:**

1. Ship a local, non-consensus release that rejects unsolicited file transfers and `SETCFGDATA`, restricts zip extraction, and turns off auto-update unless signed. Those changes close C-01, C-02, H-05 and H-06 for most practical purposes, and they do not need a coordinated upgrade. This release itself depends on the unsigned update channel, or on operators installing by hand.
2. Plan a coordinated upgrade for the consensus fixes: C-04, C-05, C-06, C-07, H-01 and H-07, in one activation.
3. Treat key custody as an open question: who holds the admin key and the `nosocoin` GitHub organization (H-03, C-08).

## Severity table

Status: **Confirmed** means established by reading the code path. **Suspected** means it depends on code outside the tree or on run-time behaviour.

| ID | Severity | Title | Status | Consensus change | Fix status |
|---|---|---|---|---|---|
| C-01 | Critical | Forged network configuration on a 20-bit MD5 prefix | Confirmed | Full fix yes, stopgap no |
| C-02 | Critical | Unsolicited `BLOCKZIP` file write in node directory | Confirmed (escape from directory: suspected) | No | Fixed: an archive is accepted only as the answer to a block request sent on that connection (`takeReply`), is read into memory and never extracted, and flat `<n>.blk` entries only. Pushed archives and state files (`RESUMENFILE`, `SUMARYFILE`, `GVTSFILE`, `PSOSFILE`) end the connection. `TestC02_H05_H06_UnsolicitedFilesRefused`. |
| C-03 | Critical | Downloaded blocks, summary and headers not validated | Confirmed | Yes (node side) | Blocks enter the chain only through `acceptRunLocked`: canonical encoding, parent link, proposer seal, header fields pinned, every order, state transition and the state root the block commits to are checked before anything is stored (`ValidateBlock`, `evalBlock`). Summary and headers files are derived and replayed with each block's state root checked. Network side (re2): no seed vote decides which block is taken. A new tip is announced by PING and pulled by number or tip hash from the peer that shows it, and the answer goes through `StageBlocks` only. The summary, headers, GVT and PSO files are never downloaded (they are derived from the blocks); a peer that pushes one is cut off. `blocksMatchHeaders` is deleted. `TestDevnetBlocksSpreadWithoutSeedVotes`, `cmd/nosod TestNetworkOfProcesses`. `TestRE2_ReencodedBlockRefused`, `TestRW_ForgedSpendRejected`, `TestRE2_ChainAcrossBoundary`. |
| C-04 | Critical | Replay of signed transfers | Confirmed | Yes | Fixed: `TrfrID` derived from all signed fields, checked in every received block; replay closed by the order time window plus the previous-block id test. `TestC04_TrfrIDBoundAndReplay`, `TestRW_StateRulesEnforced`. |
| C-05 | Critical | `amount + fee` overflow mints coins | Confirmed | Yes | Fixed: amounts range and overflow checked everywhere; shares use 128-bit products (`consensus.ApplyBP`, `Shares`), the masternode check no longer multiplies (16384 x 2^50 wrapped). `TestC05_Overflow`, `TestRW_MNShareChecked`. |
| C-06 | Critical | `CUSTOM` fee mints coins | Confirmed | Yes | Fixed: exact fee, amount 0, valid unused alias (unique across blocks); the pool check uses the fee of the block the order will land in (161999 boundary). `TestC06_CustomFee`, `TestRW_AliasAcrossBlocks`. |
| C-07 | Critical | Forged masternode checks divert rewards | Confirmed | Yes | Fixed (node side, with the trust-model limit below): validators registered per IP; every received masternode report is challenged with `MNVER <nonce>` before it is listed, so a report cannot be listed for an IP that does not answer. `TestMNChecksSecurity`, `TestC07_ReportNeedsAnsweringIP`. The IP slot is taken only after the challenge is answered, so a funded key can no longer burn another node's slot by naming its IP (final audit F-5, `TestFinal_FailedReportDoesNotBurnTheIPSlot`; with one queued report per fund in the network layer). Not closed: the proposer's masternode list is trusted for completeness (trust model, `docs/consensus.md`). |
| C-08 | Critical | Auto-update runs unsigned code | Confirmed | No |
| H-01 | High | Masternode reports unauthenticated, first report unchecked | Confirmed | Yes | Fixed: reports signed by the funds key or, for cold funds, by the sign key under a one-time delegation; funds check applies to every report. `TestMNReportSecurity`, `TestRW_ColdFundsReport`. |
| H-02 | High | Admin directives replayable | Confirmed | No |
| H-03 | High | One admin key is global root | Confirmed (design) | Yes |
| H-04 | High | Plurality vote with no quorum on 20-bit values | Confirmed | Partly | Fixed for blocks and state: no block, summary, header, GVT or PSO is taken or deleted on a vote any more (re2 C1, H-5, M-3). The vote (quorum over all configured seeds, one vote per host and port) remains only as a hint for the configuration, the masternode file and list and the verification records, and each of those is checked on its own (full hash, signature). Not fixed: those votes are still 5-character prefixes, and `SeedKeys` stays empty by default (status is plain TCP, so an on-path attacker can fake a vote that is only a hint). `TestH04_QuorumAndDedupe`, `TestM7_NullIsNotASeed`. |
| H-05 | High | Headers corruption forces desync | Confirmed | No | Fixed by removal: headers are derived from the blocks, never requested, and `HEADUPDATE`/`RESUMENFILE` answers are not accepted (the peer is cut off). An honest peer is no longer closed for headers that differ from our blocks (re2 H-3). `TestC02_H05_H06_UnsolicitedFilesRefused`. |
| H-06 | High | `MNFILE` and `PSOSFILE` overwrite state | Confirmed | Partly | Fixed: `MNFILE` needs the voted full hash and a request on that connection; `PSOSFILE` and `GVTSFILE` are never accepted (state is derived from blocks). `TestMNFileNeedsFullHash`, `TestC02_H05_H06_UnsolicitedFilesRefused`. |
| H-07 | High | Unsigned fields, ambiguous signed text | Confirmed | Yes | Fixed: canonical signed encoding (tag, chain id, domain, length-prefixed fields including type and reference). Final round: the line count of a wire order is signed too, and the pool admits only complete, consistent groups. `TestCanonicalSignVerify`, `TestC04_TrfrIDBoundAndReplay`, `TestFinal_PrefixOfMultiLineOrderRefused`, `TestFinal_OrderLinesCannotSwallowOthers`. |
| H-08 | High | Signed bytes pass through lenient Base64 | Suspected | Yes | Fixed (re2 H-1): keys and signatures must be canonical Base64 and canonical low-S DER, one text per signature; lenient decoder only for legacy private-key text. `TestStrictBase64`, `TestDERStrict`, `TestVerifyCanonicalRejectsTextVariants`, `TestECDSAIndependentVector`. |
| H-09 | High | RPC unauthenticated and reachable by CSRF | Confirmed | No |
| H-10 | High | Keys in clear, in logs and in crash reports | Confirmed | No | Partly fixed (cli/rpc/nosod side): RPCSaveNew writes no plaintext files, exports are 0600 and exclusive with a warning, passphrase minimum 8 on creation. Storage side (re2): an unreadable or torn wallet is an error, the newest verified source wins and none is erased, backups are never overwritten by smaller data, wallet files 0600 and data dir 0700, cross-process `LockDataDir`; the warning and the `wallet retire-legacy` command exist (`Wallet.LegacyWarning`, `Wallet.RetireLegacy`). `RetireLegacyWallet` refuses any copy with an unparsed tail or a key `wallet.enc` lacks, covers `*.damaged-*`, `*.bak.*.old` and `SUMMARKS/RPC/*.pkw` (and the start-up warning lists them), and never follows a link (final audit F-7, `TestFinalRetire*`). Journal-copy shredding on journalled or flash storage stays best effort. Windows ACLs are not set. `TestRE2*`. |
| H-11 | High | Stalled or oversized transfers block sync | Confirmed | No | Fixed: transfers are read outside the heartbeat lock with an idle and a total deadline; block archives are applied outside it too (re2 M3); files are read and sent from a goroutine of their own, one per slot and eight at once; an archive carries as many consecutive blocks as fit 32 MiB so full blocks can be synced (re2 consensus 8). `TestStalledTransferDoesNotBlockTick`, `TestBlockArchiveIsBounded`. |
| M-01 | Medium | Alias rules client-side only, order type unchecked | Confirmed | Yes | Fixed: receiver-side alias rules, only `TRFR`/`CUSTOM`/`SNDGVT` in blocks, alias unique across blocks. `TestM01_OrderType`, `TestRW_AliasAcrossBlocks`. |
| M-02 | Medium | TLS verification and bootstrap trust | Partly suspected | No |
| M-03 | Medium | Time from one unauthenticated NTP reply | Confirmed | No |
| M-04 | Medium | Peers set a node's own IP | Confirmed | No |
| M-05 | Medium | Masternode liveness proof is weak | Confirmed | Yes |
| M-06 | Medium | Data races | Partly suspected | No |
| M-07 | Medium | Main-thread work with no peer budget | Confirmed | No | Fixed: per-command line caps, per-slot byte and `$MNREPO` budgets, byte-bounded incoming queue; lines that answer `$GETMNS`/`$GETPENDING` (reports, orders) have a bulk budget so an honest requester is not cut off (re2 H5), `$GETMNS`, `$GETPENDING` and `GETMNSFILE` are rate limited per peer (re2 M-2). Reports are parsed, bound to the block and stake-checked before they use an IP slot or a dial (re2 H-3, M-1); the queue is capped and shutdown does not wait for it. The node-side tables are bounded too (4096 entries each, re2 M-2). `TestH5_BulkLinesHaveTheirOwnBudget`, `TestH3_ReportCheckedBeforeIPSlotAndDial`, `TestM1_OwnIPAloneIsChallenged`. |
| M-08 | Medium | Costly requests with no rate limit | Confirmed | No | Fixed: per-peer limits on heavy one-shot requests; accepted connections that are not yet peers are capped (64) and closed on shutdown (re2 M8). `TestPendingConnectionsBounded`. |
| M-09 | Medium | Unchecked binary file parsing | Confirmed | No |
| M-10 | Medium | Block content depends on local mempool | Confirmed | Yes | Reworked (re2): fixed proposer list bound to the chain by a digest in every block, sealed blocks, header fully pinned, fork choice by score (skipped slots cost weight), then earlier tip, then lower hash, with no local finality in the decision; blocks spread by PING and pull, no vote. A block for another proposer's slot waits `OutOfTurnGrace`. Accepted trust limit, not a bug: any proposer can censor and can rewrite history at any depth (`docs/consensus.md`). Equivocation is not recorded. `TestRE2_TipSnipeFails`, `TestRE2_NoFinalitySplit`, `TestRE2_ProposerListBound`, `TestRW_ForkChoiceConverges`, `TestFinal_DeepForksResolve`, `TestFinal_OutOfTurnBlockWaitsForTheGracePeriod`. |
| M-11 | Medium | Build and replay produce different summaries | Confirmed (hash effect inferred) | No | Fixed (re2): one state transition for builder, validator and replay, replay commits block by block like forward validation and checks each block's state root. The earlier batch replay refused valid masternodes (found in re2). Known gap: legacy (pre-trailer) replay does not touch masternode locks. `TestRE2_RebuildAcceptsValidMN`, `TestRW_BuilderNeverExceedsValidator`. |
| M-12 | Medium | Non-atomic state, ignored write errors | Confirmed | No | Fixed (storage, re2 #7): fsync for every state file, atomic copies, gvts/psos errors returned, `Txn` journal for multi-file commits (the node does not use `Txn`; it has its own journal, below). Fixed (node, re2): journal with a commit point, durable snapshots, recovery at start, state-root check at start, write failures after the commit point recovered from the journal (`commit.go`). Final round: genesis is written again at every start until block 1 (a crash while it was written used to fork the node for good), the undo data of a new branch is in place before the journal is dropped and that of an abandoned branch is removed at the commit point, recovery does not rewrite the journal it runs from, and a tip file that is not the block the headers recorded is no longer a healthy start (`TestFinal_CrashDuringGenesisEveryPoint`, `TestFinal_CrashDuringReorgEveryPoint`, `TestFinal_DamagedTipIsAHardError`). Earlier "fixed" covered failed writes only; a crash between state and block wrote coins into local state. `TestRE2_CrashSummaryAheadHeals`, `TestRE2_JournalRecovery`. `TestRW_FailedWriteRetryPaysOnce`, `TestM12_WriteFailureStopsBuild`. |
| M-13 | Medium | SHA-1, MD5, signature malleability | Confirmed | Yes | Fixed at the text layer (strict Base64 and DER in `VerifyCanonical`, crypto) and at the block layer: a re-encoded block (changed signature text) is refused, so the block hash cannot be changed without the key. The earlier claim was false for blocks (anyone could swap the tip). `TestLowSEnforced`, `TestDERStrict`, `TestRE2_ReencodedBlockRefused`. |
| M-14 | Medium | GVT state and rule problems | Confirmed | Partly | Fixed: owner key authorises, ownership checked before the debit, canonical reference (pool admission now refuses any other spelling), and the 100 GVT records are created by block 1 for its sealer so they exist, can be signed for, and survive a rebuild. `TestM14_GVTOwner`, `TestFinal_FirstBlockCreatesTheGVTs`, `TestFinal_SendGVTReferenceIsCanonical`. |
| M-15 | Medium | Unchecked indexes and casts | Confirmed | No |
| M-16 | Medium | Unpinned CI, binary blobs | Confirmed | No |
| L-01 | Low | Address checks accept unspendable forms | Confirmed | Partly | Partly fixed: `M` addresses and over-long names refused; the sum checksum is kept (swapped characters still pass). `TestL01_L08_Receivers`. |
| L-02 | Low | `IsValidIP` accepts private ranges | Confirmed | Yes |
| L-03 | Low | Lock and result errors | Confirmed | No | Fixed: unparsable orders are errors, first error code kept. `TestL03_ResultsAtEntry`. |
| L-04 | Low | Global rate limits | Confirmed | No | Fixed: the limits are per peer (per connection for loopback peers, which share an address). `TestRateLimits`. |
| L-05 | Low | Certificates have no audience | Confirmed | No |
| L-06 | Low | `GetSupply` wrong after block 210000 | Confirmed | No | Fixed: `GetSupply` follows the halving schedule and the coins in existence equal it: the unpaid masternode share goes to the miner and nothing is burnt (`TestFinal_UnpaidMasternodeShareGoesToTheMiner`, `TestSupply`). |
| L-07 | Low | Unbounded logging of peer text | Confirmed | No |
| L-08 | Low | Address truncation in fixed fields | Confirmed | Partly | Peer addresses are kept up to 45 bytes (IPv6 duplicate and ban checks match). The RPC whitelist splits host and port with the standard library and compares addresses, so an IPv6 caller no longer matches the end-of-list marker (re2 L7). `TestL7_IPv6Whitelist`. |

## Final audit (round after re2)

Status of the final audit's findings and of the consensus, operator and completeness reviews that went with it. "Trust model" means the owner decided the behaviour is a documented limit of a proposer chain, not a defect (`docs/consensus.md`).

| Ref | Finding | Status |
|---|---|---|
| F-1 | One proposer rewrites history at any depth | Accepted, trust model: proposers are fully trusted, there is no finality, the documents say so and no longer offer a confirmation count |
| F-2 | One peer stops proposers building and owns block pull | Fixed: a claimed height never stops building, an impossible claim is ignored, block pull rotates and holds back peers that fail it. `TestClaimedHeightNeverStopsBuilding`, `TestImpossibleClaimIsNeverPulled`, `TestPullRotatesAndHoldsBackLiars` |
| F-3 | A free order evicts honest orders | Fixed for the free variant: `OrderLines`/`TrxLine`/`OrderID` checked at pool admission, the builder judges a malformed line alone, the pool is bounded and refuses instead of evicting. Not closed: a funded flood of valid orders can still delay honest ones for a period at the price of the fees of the ~2000 it gets mined (no fee market). `TestFinal_OrderLinesCannotSwallowOthers`, `TestFinal_PoolIsBounded` |
| F-4 | A proposer lists only itself for the masternode pool | Accepted, trust model; the unpaid share now goes to the miner as in the original (no burn), so supply equals `GetSupply`. `TestFinal_UnpaidMasternodeShareGoesToTheMiner` |
| F-5 | One stake burns report slots | Fixed: the IP slot is taken after the `MNVER` challenge. `TestFinal_FailedReportDoesNotBurnTheIPSlot` |
| F-6 | Control socket hands out keys | Fixed: key commands over the socket need the passphrase. `TestControlSocketKeepsKeysBehindThePassphrase` |
| F-7 | `wallet retire-legacy` can destroy a key | Fixed: whole-record check, all copies covered, links refused. `TestFinalRetireRefusesATornTail`, `TestFinalRetireCoversEveryCopyAndNeverFollowsLinks` |
| F-8 | Staged branch memory and lock time | Fixed (node side): bounded in blocks and bytes, each window verified once, future/off-grid blocks refused before they are kept, a stale stage is dropped. `TestFinal_StagedBranchIsBounded`, `TestFinal_StaleStagedSiblingDoesNotPoisonTheNextBlock` |
| F-10 | Fake entries in `getpendingorders` | Fixed: the fields are cleaned |
| F-11 | 99 inbound peers fill every slot | Fixed: slots reserved for outbound, inbound limited per network. `TestInboundCannotFillEverySlot`, `TestInboundLimitedPerNetwork` |
| F-18 | Same chain id on every network | Changed: the chain id of the network file is signed into every order and its transfer id. `TestOrderSignedOnAnotherNetworkIsRefused`, `TestBlocksCommitToTheNetworkFile`, `TestParseNetworkConfigIsStrict`, `TestInitNetworkWritesNetworkFile` (written, not run). |
| F-9, F-12..F-17, F-19, F-20 | See the final audit | Open |
| consensus 2 | Crash while genesis is written forks the node | Fixed: `TestFinal_CrashDuringGenesisEveryPoint`, `TestFinal_DoubleCrashDuringGenesis` |
| consensus 3 | Forks between probe windows never found | Fixed: `TestFinal_DeepForksResolve` (depth 170 and 330) |
| consensus 4 | Out-of-turn proposer takes a slot | Fixed: `OutOfTurnGrace`. `TestFinal_OutOfTurnBlockWaitsForTheGracePeriod` |
| consensus 6 | Stale `UNDO/N` after a crash | Fixed: `TestFinal_CrashDuringReorgEveryPoint` |
| consensus 7 | Prefix of a multi-line order | Fixed: the line count is signed. `TestFinal_PrefixOfMultiLineOrderRefused` |
| consensus 11 | "Same blocks, same chain" depends on delivery order | Documented: it heals through the next pull |
| consensus 3b | Unsealed block reported as wrong parent | Fixed: seal checked first, `ErrUnsealed`, the sync layer strikes at once. `TestFinal_UnsealedBlockIsDistinctFromAForkParent` |
| consensus 12 | Damaged tip passes the start check | Fixed: `TestFinal_DamagedTipIsAHardError` |
| operator (high) | Every order refused (code 4) once the tip is a slot old | Fixed: the pool bound is the node's clock plus 60 s; block validation never used it. `TestFinal_OrdersAreAdmittedWhileTheTipIsStale` |
| operator (critical) | A node that never builds keeps every relayed order | Fixed: every accepted or built block prunes the pool. `TestFinal_FollowerPrunesMinedOrders` |
| completeness GAP-1 | Mined orders not found | Fixed: indexed at commit, rolled back on reorganisation. `TestFinal_MinedOrdersAreIndexed`, `TestFinal_ReorgRollsBackOrderIndex` |
| completeness GAP-2 | No GVT on a new chain | Fixed: created by block 1 for its sealer. `TestFinal_FirstBlockCreatesTheGVTs`, `TestFinal_SendGVTReferenceIsCanonical` |
| completeness GAP-3 (b), GAP-4, GAP-5 | `sendgvt` reference, wallet balance, `newpso` | Node side fixed (`SendGVT` reference, `RefreshWalletBalances`); `newpso` / `clearpsos` now sign orders that blocks carry (`NEWPSO`, `CLRPSO`, `docs/consensus.md`), tests `TestPSOOrderMinedOnTwoNodesSameStateRoot`, `TestPSOUndoneByReorgAndMinedAgain` (written, not run) |

## Scope

- **In scope:** the live build as defined by `Noso.lpr` and `Noso.lpi`, the network protocol, block and summary logic, consensus, masternodes, GVT and PSO code, RPC, wallet storage, auto-update, time sync, and the CI workflow as it affects released binaries.
- **Packages:** `Packages/` was reviewed only where consensus or crypto depends on it: Indy stream and timeout code, CryptoLib ECDSA and RNG selection, HashLib output.
- **Out of scope:** `Deprecated/`, which the live build does not use, the root file `mpmn.pas`, also not referenced by the build, GUI layout, and the `docs_site/` content, which was treated only as untrusted text. It also disagrees with the code in places: for example it says signing uses SHA-256, while `mpsignerutils.pas:54` uses SHA-1.

## Method

Each live unit was read in full, with the handlers traced from socket read to state change. For each claim, callers and call sites were followed, and search was used to confirm absences, for example that nothing verifies `TrfrID` or compares `RPCPass`. Quoted code in this document is copied by script from the source files at the stated line numbers, not retyped. Vendored zips were extracted to a scratch folder and read there.

## Limits

- **Static reading only.** Nothing was built, run, fuzzed or connected to any network. No live node was touched. Impact statements are reasoned from the code, not observed.
- **FPC runtime library is not in the tree.** These behaviours are recalled, not verified, and each should be confirmed with an offline test:
  - `DecodeStringBase64` default non-strict filtering and handling of an incomplete final group (H-08).
  - `TUnZipper` handling of `..`, absolute paths and symlinks (C-02).
  - `TFPHTTPClient` certificate verification default (M-02).
  - Whether assigning a shorter value to a ShortString leaves the old tail bytes (Go rewrite notes).
  - `Copy(s,0,5)` returning the first five characters, which the voted values depend on (Go rewrite notes).
- **No live data.** Current height, seed status, and whether historic blocks contain any of these patterns were not examined.
- **Binary files** (`ssl/*.dll`, `.rar`, zips beyond the files named) were not audited, and published release binaries were not inspected. C-05 assumes they follow the CI build mode.
- **Severity** assumes default settings unless stated, and treats the network as live.


## Notes for a compatible Go rewrite

A compatible node must reproduce the bytes of blocks and of the summary, because those bytes are hashed and voted on. So some bugs below cannot simply be fixed. Treat this section as a compatibility contract, and confirm each item with test vectors from real chain data.

### Must preserve for compatibility

These affect historical replay or the live hash vote. Changing them makes a node disagree with the network.

| Behaviour | Where | Note |
|---|---|---|
| Signature preimage: lenient `DecodeStringBase64` of the text, then SHA-1, ECDSA on secp256k1, DER | `nosocrypto.pas:231-242`, `mpsignerutils.pas:54` | H-08 and M-13. Copy the decoder exactly, including any treatment of a final partial group. Go's strict Base64 will not match. |
| Message templates with no separators | `mpprotocol.pas:762`, `:792`, `:973`, `:1016` | H-07 |
| Address derivation: SHA-256 of the Base64 key text, hex text, RIPEMD-160 of that hex text, `BMHexTo58`, sum checksum | `nosocrypto.pas:245-258` | Hex comes from HashLib `ToString`. `FutureGetAddressFromPublicKey` is an experiment, not the rule. Check leading-zero behaviour. |
| Summary format: packed 106-byte records, new addresses appended in `BlockRecords` order, record 0 carries `LastOP` | `nosounit.pas:18-24`, `:529-557` | Follow the build path, not `AddBlockToSumary` (M-11). Note that `IsCustomizacionValid`'s `BlockRecords` branch does not update `LastOP`, unlike its disk branch. |
| Block format: packed records, fixed ShortString capacity, every byte hashed by MD5 of the file | `nosoblock.pas:25-40`, `nosogeneral.pas:26-41` | ShortString tails may keep old bytes after a shorter value is assigned (`mpblock.pas:199`, `:212`, public key replaced by address). Confirm against real `.blk` files. |
| Block construction order: pool sort by timestamp, `OrderID`, `TrxLine`, the 60-second rule, the 2000 limit, then project order, PoS, masternodes | `nosonetwork.pas:281-329`, `mpblock.pas:170-266` | M-10. The header fields hold repurposed values: `Difficult`, `NxtBlkDiff`, `Solution`. |
| The `CUSTOM` mint: `MinerFee` takes the wire value, while 25000 is debited | `mpblock.pas:197`, `nosounit.pas:510`, `:522` | C-06. History contains this, at least for the honest 1000000 fee. |
| Wrapping `Int64` arithmetic in historic replay | `Noso.lpi:70-85` | C-05. Go's `int64` wraps the same way. Do not use checked maths in the replay path. Accept negative balances if they exist in history. |
| Reward formulas with their exact order of integer operations | `mpblock.pas:262`, `:333-336`, `:352` | Remainders go to the miner address. |
| Height-dependent rules, with their inconsistencies | `nosogeneral.pas:278-323`, `masterpaskalform.pas:606-615` | `88400` against `88500`, block `53000` header rule, `162000` custom fee, `120000` lock rule, `110000` stake. |
| Old blocks are loaded, not rebuilt | `mpblock.pas:292-298` | `BuildNewBlock` divides by a zero `PoScount` for blocks in the PoS range. |
| `N4Pe...` literal as the "last op" record in building | `mpblock.pas:355` | M-11 |
| Masternode file text: spacing, `;` and `:` separators, age counter, trailing `CRLF` in the hash | `nosomasternodes.pas:507-528`, `:812-828`, `mpprotocol.pas:1113` | Duplicate validations count (C-07). `String[32]` truncation applies (L-08). |
| `MinValidations := (checks div 2) - 1`, 2016-block lock, verificator count | `nosomasternodes.pas:514`, `:907`, `nosopsos.pas:67` | |
| Voted-value format: 5-character prefixes and `GetConHash` input fields | `nosoconsensus.pas:215-221` | FPC `Copy(s,0,5)` returns the first 5 characters. |
| Wire parsing | `nosogeneral.pas:133-181`, `mpprotocol.pas:93-121` | `Parameter()` groups by parentheses. `StrToInt`-family calls are recalled to accept forms such as `$FF` and leading `+`. The signed text uses the re-printed number, so test these. |
| CFG semantics while the network uses them | `mpblock.pas:128-133`, `:233-258` | Including `NOSOPAY` execution of already accepted directives, and `STOP`, `EMPTY`, `MNSONLY`. |

### Can harden without a consensus change

These do not change block or summary bytes for honest traffic.

- Accept file transfers only in reply to a pending request on that connection, and verify them before storing (C-02, C-03, H-05, H-06).
- Do not extract zips to disk. Read named entries from memory, with size limits (C-02).
- Drop unsolicited `SETCFGDATA` and `MNFILE`, and compare full hashes wherever peers supply them. `$PING` carries full block, summary and headers hashes (C-01, H-06).
- Add deadlines and size limits on every read, plus per-peer quotas. Go's memory safety also removes M-06, M-09 and M-15 as memory issues, though logic races remain possible.
- Validate received blocks by recomputing them, and refuse any that cannot be reproduced. Keep this in report-only mode first, so that historic quirks can be found.
- Require a quorum and a depth limit before rolling back (H-04). Deduplicate the seed list locally. Note that a node with a stricter vote can disagree with others during an incident. That is intended.
- Authenticate RPC, bind it to loopback and add CSRF protection (H-09).
- Encrypt wallets and keep keys out of logs (H-10).
- Verify release signatures, and drop auto-execution by default (C-08).
- Use several NTP sources with a bound (M-03), and ignore peer input about the node's own IP (M-04).
- Never build a `NOSOPAY` transfer, or any CFG field, from unverified data (C-01).

### Looks local, but is not

Filtering orders in the mempool changes the block that node would build. A Go node that rejects C-04, C-05 or C-06 patterns will build a different block from the rest of the network when one appears, then lose the vote. Such a node has two options:

- **Follower mode:** do not rebuild blocks at all, and accept validated network blocks, in which case an attack on the network still becomes its chain.
- **Alert mode:** detect the pattern, stop and raise an alarm for an operator decision.

Either is better than silently diverging. Do not mix strict rules into block building before the network has agreed on an activation height.

### Needs a coordinated network change

Fix these at one activation height, keeping the old rules for all earlier blocks:

- Bound `TrfrID`, a real replay rule and a canonical signed encoding with SHA-256 and low-S (C-04, H-07, H-08, M-13).
- Amount range checks and an exact `CUSTOM` fee (C-05, C-06).
- Signed masternode reports and checks, and a challenge-based verifier (C-07, H-01, M-05).
- Signed CFG with removal of unsigned `NOSOPAY` (C-01, H-03).
- Full-length hashes and a defined block proposer or block commitment (C-03, H-04, M-10).
- Alias rules (M-01) and GVT rules (M-14).


## Critical findings

### C-01. Forged network configuration accepted on a 20-bit MD5 prefix

- **Severity:** CRITICAL. An unauthenticated peer can change the configuration that every affected node uses to build blocks. That configuration can move any balance, halt block production, freeze addresses and replace the consensus seed list.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:277`, `mpprotocol.pas:1064-1080`, `mpblock.pas:128-133`, `mpblock.pas:233-258`, `mpred.pas:613-622`, `masterpaskalform.pas:1699`.

`mpprotocol.pas:1064-1080`
```pascal
Procedure PTC_CFGData(Linea:String);
var
  startpos : integer;
  content : string;
Begin
  startpos := Pos('$',Linea);
  Content := Copy(Linea,Startpos+1,Length(linea));
  if Copy(HAshMD5String(Content),0,5) = GetCOnsensus(19) then
    begin
    SaveCFGToFile(content);
    SetCFGDataStr(content);
    FillNodeList;
    ToLog('events','Noso CFG updated!');
    end
  else
    ToLog('events',Format('Failed CFG: %s <> %s',[Copy(HAshMD5String(Content),0,5),GetCOnsensus(19)]));
End;
```

`mpblock.pas:233-258`
```pascal
   if GetCFGDataStr(6) <>'' then
      begin
      NosoPayData := GetCFGDataStr(6);
      NosoPayData :=StringReplace(NosoPayData,':','',[rfReplaceAll, rfIgnoreCase]);
      NosoPayData :=StringReplace(NosoPayData,',',' ',[rfReplaceAll, rfIgnoreCase]);
      NPDBlock := StrToIntdef(Parameter(NosoPayData,0),0);
      if NPDBlock = numero then
         begin
         NPDSource := Parameter(NosoPayData,1);
         NPDTarget := Parameter(NosoPayData,2);
         if ( (IsValidHashAddress(NPDTarget)) and (IsValidHashAddress(NPDSource)) ) then
            begin
            NPDAmount := StrToInt64def(Parameter(NosoPayData,3),0);
            if NPDAmount > 0 then
               begin
               if SummaryValidPay(NPDSource,NPDamount,NPDBlock) then
                  begin
                  CreditTo(NPDTarget,NPDAmount,NPDBlock);
                  NPDOrder := CreateNosoPayOrder(NPDBlock,NPDSource,NPDTarget,TimeStamp,NPDAmount);
                  insert(NPDOrder,ListaOrdenes,length(listaordenes));
                  RemoveCFGData(GetCFGDataStr(6),6);
                  end;
               end;
            end;
         end;
      end;
```

- **Why it is vulnerable:** `SETCFGDATA` is dispatched for any connected slot, with no check that the node asked for it. The only gate is the first 5 hex characters of an MD5 of the content, compared with the voted CFG hash. That is 20 bits, so matching it needs about a million MD5 computations. The content carries no signature, although the same settings are admin-signed when they arrive through `ADMINMSG`. Because the new content keeps the same 5-character hash, `mpred.pas:613` sees no mismatch and the voted `GetConHash` value does not change, so the forgery is silent. It is also saved to disk (`SaveCFGToFile`) and survives restarts.
- **What the forged fields do:**
  - Field 6 (`NOSOPAY`) is executed by `BuildNewBlock` as an unsigned transfer from any address to any address.
  - Field 0 (`NORMAL`, `STOP`, `EMPTY`, `MNSONLY`) stops block building, wipes the mempool, or changes the masternode reward share (`mpblock.pas:128-133`, `nosogeneral.pas:301`, `mpprotocol.pas:806`).
  - Field 5 freezes any address (`mpprotocol.pas:772-776`).
  - Field 2 selects the NTP servers.
  - Field 1 defines `IsSeedNode`, which decides who may send masternode checks and who may connect during sync. It also becomes the set of nodes polled for consensus at the next start (`masterpaskalform.pas:1699`).
- **Attacker and preconditions:** Anyone who can complete the plain `PSK` handshake with a node running the server, or any peer a wallet connects to out. No key, no stake and no funds are needed. The current consensus CFG hash is public through `NODESTATUS`.
- **Impact on a live network:** Reaching the plurality of seed nodes is enough to make the network accept unsigned transfers out of any address. Nodes that were not reached build a different block, lose the vote and then adopt the forged chain. A `STOP` value halts the chain until each operator repairs the file.
- **Consensus change:** Yes for a clean fix, since all nodes must adopt the same CFG acceptance rule. Dropping unsolicited `SETCFGDATA` is a local hardening with no consensus effect.
- **Fix:** Reject `SETCFGDATA` unless it answers a pending request. Compare the full hash, not a prefix. Require an admin signature over `height`, a monotonic counter and the full CFG content, and verify it before saving. Remove `NOSOPAY` execution from `BuildNewBlock`, or require an owner signature from the source address.

### C-02. Unsolicited `BLOCKZIP` gives a remote peer file write inside the node directory

- **Severity:** CRITICAL. An unauthenticated peer can overwrite or destroy `wallet.pkw`, every chain file and configuration, and can plant files that lead to code execution on some installs.
- **Status:** Confirmed by reading for writes inside the working directory. Escape outside that directory by `..`, absolute paths or symlinks is suspected, because it depends on FPC `TUnZipper`, which is not in the tree.
- **Location:** `masterpaskalform.pas:2442-2469`, `nosonetwork.pas:1259-1278`, `nosogeneral.pas:565-584`, `nosoblock.pas:413-424`.

`masterpaskalform.pas:2442-2469`
```pascal
   else if LLine = 'BLOCKZIP' then
     begin
     BlockZipName := BlockDirectory+'blocks.zip';
     TryDeleteFile(BlockZipName);
     MemStream := TMemoryStream.Create;
     DownLoadBlocks := true;
       TRY
       AContext.Connection.IOHandler.ReadStream(MemStream);
       MemStream.SaveToFile(BlockZipName);
       GetFileOk := true;
       EXCEPT ON E:Exception do
         begin
         GetFileOk := false;
         TryCloseServerConnection(AContext);
         end;
       END; {TRY}
       if GetFileOk then
         begin
         if UnzipFile(BlockDirectory+'blocks.zip',true) then
           begin
           MyLastBlock := GetMyLastUpdatedBlock();
           LastTimeRequestBlock := 0;
           ToLog('events',TimeToStr(now)+format(rs0021,[IntToStr(MyLastBlock)])); //'Blocks received up to '+IntToStr(MyLastBlock));
           end
         end;
       MemStream.Free;
       DownLoadBlocks := false;
     end
```

`nosogeneral.pas:565-584`
```pascal
Function UnzipFile(filename:String;delFile:boolean):boolean;
var
  UnZipper: TUnZipper;
Begin
  Result := true;
  UnZipper := TUnZipper.Create;
    TRY
    UnZipper.FileName := filename;
    UnZipper.OutputPath := '';
    UnZipper.Examine;
    UnZipper.UnZipAllFiles;
    EXCEPT on E:Exception do
      begin
      Result := false;
      ToDeepDeb('NosoGeneral,UnzipFile,'+E.Message);
      end;
    END; {TRY}
  if delfile then Trydeletefile(filename);
  UnZipper.Free;
End;
```

- **Why it is vulnerable:** The server handler runs for any inbound slot that sent the word `BLOCKZIP`. Nothing checks that blocks were requested, that the archive holds only `<number>.blk` entries, that block numbers are expected, or that sizes are sane. `OutputPath` is empty, so entries are written relative to the process working directory. The node's own archives store names such as `NOSODATA/BLOCKS/123.blk`, so an entry name like `NOSODATA/wallet.pkw` needs no traversal trick at all. The same path exists on outbound connections in `TThreadClientRead` (`nosonetwork.pas:1259-1278`).
- **What can be written:**
  - `NOSODATA/wallet.pkw` and its `.bak`, which destroys private keys for which the user may have no other copy.
  - `NOSODATA/advopt.txt`, which changes `MNFunds` (redirecting masternode rewards) and RPC settings at next start.
  - `NOSODATA/BLOCKS/*.blk`, `sumary.psk`, `nosocfg.psk`, `gvts.psk`.
  - On Windows, `libeay32.dll` and `ssleay32.dll`. `masterpaskalform.pas:3233-3236` shows these are expected in the working directory, so a planted DLL can execute on next load if the file is not already loaded.
  - A high-numbered `.blk`, which makes `GetMyLastUpdatedBlock` report a false tip (`nosoblock.pas:328-354`).
- **Attacker and preconditions:** Any peer that passes the handshake on a node with the server active, while `MyConStatus = 3`. For a wallet with no server, any node in its `NodesList` that it connects to.
- **Impact on a live network:** Remote destruction of wallets and of masternode state, reward redirection and possible remote code execution. Disk exhaustion by zip bomb is a side effect, since extraction has no size limit.
- **Consensus change:** No.
- **Fix:** Accept `BLOCKZIP` only as the reply to an outstanding request on that exact connection. Extract to a temporary directory, or better, decode in memory. Allow only entries matching `^[0-9]+\.blk$` with a flat name, reject links and absolute or relative parents, and cap entry count, single size and total size. Move each block into place only after C-03 validation.

### C-03. Downloaded blocks, summary and headers are not validated

- **Severity:** CRITICAL. The ledger a node adopts is whatever a peer supplies, subject only to a 20-bit check that a peer can satisfy offline.
- **Status:** Confirmed by reading.
- **Location:** `nosonetwork.pas:1194-1278`, `nosounit.pas:197-208`, `mpred.pas:510-513`, `mpred.pas:666-708`, `mpred.pas:817-835`, `mpdisk.pas:631-657`.

`nosonetwork.pas:1210-1225`
```pascal
          else if Parameter(LLine,0) = 'SUMARYFILE' then
            begin
            DownloadSumary := true;
            MemStream := TMemoryStream.Create;
            if GetStreamFromClient(FSlot,MemStream) then SavedToFile := SaveSummaryToFile(MemStream)
            else SavedToFile := false;
            if SavedToFile then
              begin
              UpdateMyData();
              CreateSumaryIndex();
              end
            else killit := true;
            LastTimeRequestSumary := 0;
            MemStream.Free;
            DownloadSumary := false;
            end
```

`mpred.pas:510-513`
```pascal
if ( (MyConStatus = 2) and (STATUS_Connected) and (IntToStr(MyLastBlock) = Getconsensus(2))
     and (copy(MySumarioHash,0,5)=GetConsensus(17)) and(copy(GetResumenHash,0,5) = GetConsensus(5)) ) then
   begin
   GetValidSlotForSeed(ValidSlot);
```

`mpred.pas:817-835`
```pascal
Function GetValidSlotForSeed(out Slot:integer):boolean;
const
  SlotCount : integer = 0;
var
  counter : integer;
Begin
  Result := false;
  for counter := 1 to MaxConecciones do
    begin
    Inc(SlotCount);
    if SlotCount > MaxConecciones then SlotCount := 1;
    if ( (GetConexIndex(SlotCount).MerkleHash = GetConsensus(0)) ) then
      begin
      result := true;
      slot := SlotCount;
      break;
      end;
    end;
End;
```

- **Why it is vulnerable:** There is no function that validates a block. A search of the live units finds no check, on receipt, of `LastBlockHash` linkage, order signatures, balances, reward amounts, timestamps or headers-file membership. `BuildNewBlock` trusts its own mempool, and everything else trusts the file received. Only these comparisons exist:
  - `MyLastBlockHash` against the voted hash of the tip only. Intermediate blocks are not compared with anything.
  - The first 5 hex characters of the MD5 of the whole summary file and of the headers file.

  A summary is a flat array of 106-byte records, so an attacker can set any balance and then vary one spare byte until the 20-bit prefix matches. `SUMARYFILE`, `GVTSFILE`, `PSOSFILE`, `RESUMENFILE` and `BLOCKZIP` are all accepted on outbound connections without having been requested. `GetValidSlotForSeed` chooses a download source by the peer's own self-reported `MerkleHash`, which a peer can copy from public `NODESTATUS` output.
- **Attacker and preconditions:** Any peer a node connects to. Outbound targets come from `NodesList`, which is CFG field 1 plus the oldest masternodes (`nosonetwork.pas:1435`). A masternode that has aged into the verificator set therefore qualifies, as does anyone who has used C-01 or H-06 to alter the list. Nodes that are behind and new nodes are the easiest victims because they download by design.
- **Impact on a live network:** A victim node, for example an exchange or a new wallet, sees forged balances and treats fake deposits as real. It then reports status 3 ("Updated"), because `mpred.pas:510-511` accepts the prefix match. A forged summary overwrites any state, including alias ownership, and it replaces a correct local summary on a synced node as well.
- **Consensus change:** Adding verification of historic rules is not a change if the rules match history exactly (see the Go rewrite notes). Replacing the 5-character prefixes with full hashes in the vote is a coordinated protocol change, although peers already send full hashes in `$PING`.
- **Fix:** Add a block validator run before a block is stored: number, parent hash, time slots, reward arithmetic, signature for each order, balance replay. Require a full-length SHA-256 commitment for summary and headers in each block or in a signed checkpoint. Reject unsolicited file transfers. Verify a full hash before writing, and write to a temporary file first.

### C-04. Signed transfers can be replayed because `TrfrID` is not bound to the transfer

- **Severity:** CRITICAL. Anyone who sees one signed transfer can make the sender pay it repeatedly, up to the sender's whole balance. No key is needed.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:779-811`, `mpprotocol.pas:883-915`, `nosonetwork.pas:260-278`, `nosonetwork.pas:332-348`, `mpblock.pas:173-185`, `mpcoin.pas:297-300`.

`mpprotocol.pas:782-795`
```pascal
if GetAddressBalanceIndexed(Origen)-GetAddressPendingPays(Origen) < Order.AmmountFee+order.AmmountTrf then
   result:=1
else if TranxAlreadyPending(order.TrfrID ) then
   result:=2
else if Order.TimeStamp < LastBlockData.TimeStart then
   result:=3
else if Order.TimeStamp > LastBlockData.TimeEnd+600 then
   result:=4
else if TrxExistsInLastBlock(Order.TrfrID) then
   result:=5
else if not VerifySignedString(IntToStr(order.TimeStamp)+origen+order.Receiver+IntToStr(order.AmmountTrf)+
   IntToStr(order.AmmountFee)+IntToStr(order.TrxLine),
   Order.Signature,Order.sender ) then
   result:=6
```

`mpcoin.pas:297-300`
```pascal
OrderInfo.Signature  := GetStringSigned(ordertime+origen+destino+IntToStr(montotrfr)+
                     IntToStr(comisiontrfr)+IntToStr(linea),
                     GetWallArrIndex(WallAddIndex(origen)).PrivateKey);
OrderInfo.TrfrID     := GetTransferHash(ordertime+origen+destino+IntToStr(monto)+IntToStr(MyLastblock));
```

`mpblock.pas:173-185`
```pascal
      if ArrayPoolTXs[contador].TimeStamp < LastBlockData.TimeStart then
         continue;
      //{
      ExistsInLastBlock := false;
      for count2 := 0 to length(ArrayLastBlockTrxs)-1 do
         begin
         if ArrayLastBlockTrxs[count2].TrfrID = ArrayPoolTXs[contador].TrfrID then
            begin
            ExistsInLastBlock := true ;
            break;
            end;
         end;
      if ExistsInLastBlock then continue;
```

- **Why it is vulnerable:** The signature covers `timestamp + origin + receiver + amount + fee + line`. Duplicate protection compares only `TrfrID`. `TrfrID` is produced by the client from different data (`monto`, and `MyLastblock`), and no node recomputes it. The search for `GetTransferHash` finds only creators in the live code, never a verifier. The order ID check at `mpprotocol.pas:905` hashes the same attacker-chosen IDs, so it adds nothing. A resubmitted copy with a new `TrfrID` and a matching `OrderID` is a new, valid transfer.
- **Replay window:** An order passes while `TimeStamp >= LastBlockData.TimeStart`. Since `LastBlockData` is the previous block, a transfer stays valid in its own block and the next, so about two block intervals. The duplicate checks in `mpblock.pas:176-185` and `TrxExistsInLastBlock` both key on `TrfrID`, so they do not stop a resubmission even after the original has been mined.
- **Attacker and preconditions:** Any node peer, or any unauthenticated `NSLORDER` client. Orders are flooded on the network and are returned in full by `$GETPENDING`, so all needed data including the public key is public. The receiver gains directly from each replay, and a third party can drain a victim for spite because fees are paid each time.
- **Impact on a live network:** Theft by any payee: one payment can be turned into many, limited by the victim's balance and the window. Every node accepts the replays, so they become final.
- **Consensus change:** Yes. Which orders enter a block changes.
- **Fix:** Define `TrfrID` as a hash of every field that matters, with domain separation, and recompute it on receipt. Reject a transfer when its ID has been seen within the validity window, or add a per-address nonce stored in the summary. Bind the chain ID and block range into the signed message. Until then, a stopgap is to deduplicate on the signed tuple across the two most recent blocks plus the mempool.

### C-05. Integer overflow of `amount + fee` mints coins

- **Severity:** CRITICAL. Unlimited inflation by any address that already exists in the summary, regardless of its balance. Released binaries are built without overflow checks.
- **Status:** Confirmed by reading for the code path and for the `Release` and `Default` build modes, which have no `OverflowChecks`. Published release binaries were not inspected. If a binary was built with `-Co`, the addition raises instead, the `TRY` in `PTC_Order` catches it, and the order is rejected on that node.
- **Location:** `mpprotocol.pas:782`, `mpblock.pas:207-210`, `nosounit.pas:394-432`, `Noso.lpi:70-85`, `.github/workflows/main.yaml:54`, `:59`, `:64`.

`mpprotocol.pas:782-783`
```pascal
if GetAddressBalanceIndexed(Origen)-GetAddressPendingPays(Origen) < Order.AmmountFee+order.AmmountTrf then
   result:=1
```

`mpprotocol.pas:796-799`
```pascal
else if Order.AmmountTrf<0 then
   result := 7
else if Order.AmmountFee<0 then
   result := 8
```

`mpblock.pas:204-216`
```pascal
      if ArrayPoolTXs[contador].OrderType='TRFR' then
         begin
         OperationAddress := ArrayPoolTXs[contador].Address;
         if SummaryValidPay(OperationAddress,ArrayPoolTXs[contador].AmmountFee+ArrayPoolTXs[contador].AmmountTrf,numero) then
            begin
            minerfee := minerfee+ArrayPoolTXs[contador].AmmountFee;
            CreditTo(ArrayPoolTXs[contador].Receiver,ArrayPoolTXs[contador].AmmountTrf,numero);
            ArrayPoolTXs[contador].Block:=numero;
            ArrayPoolTXs[contador].sender:=OperationAddress;
            insert(ArrayPoolTXs[contador],ListaOrdenes,length(listaordenes));
            Inc(BlockTrfrs);
            end;
         end;
```

`nosounit.pas:419-431`
```pascal
  SendPos := GetIndexPosition(Address,ThisRecord);
  If SendPos < 0 then exit(false)
  else
    begin
    if ThisRecord.Balance<amount then Exit(false)
    else
      begin
      Dec(ThisRecord.Balance,amount);
      ThisRecord.LastOP:=Blocknumber;
      InsBlockRecord(ThisRecord,sendpos);
      Exit(true);
      end;
    end;
```

`Noso.lpi:70-84`
```xml
      <Item3 Name="Release">
        <CompilerOptions>
          <Version Value="11"/>
          <PathDelim Value="\"/>
          <Target>
            <Filename Value="Noso"/>
          </Target>
          <SearchPaths>
            <IncludeFiles Value="$(ProjOutDir)"/>
            <UnitOutputDirectory Value="lib\$(TargetCPU)-$(TargetOS)"/>
          </SearchPaths>
          <CodeGeneration>
            <SmartLinkUnit Value="True"/>
            <Optimizations>
              <OptimizationLevel Value="2"/>
```

- **Why it is vulnerable:** Both amounts are parsed by `StrToInt64`, and each is only required to be non-negative. Their sum is not range-checked. In a build without `-Co`, two large non-negative values wrap to a negative `Int64`.
  - `ValidateTrfr` then sees a balance that is not lower than a negative number and accepts the order. `TotalFee < GetMinimumFee(TotalSent)` also passes if the fee is in proportion.
  - `SummaryValidPay` receives the negative sum, finds the balance is not lower than it, and runs `Dec` with a negative value, which raises the sender's balance.
  - `CreditTo` then credits the receiver with the full unwrapped `AmmountTrf`, and `minerfee` grows by the fee.

  Only the `Debug` build mode enables checks (`Noso.lpi:44-49`). The CI builds use `--bm=Release`, and the source has no `{$Q+}` or `{$R+}` directives.
- **Attacker and preconditions:** Anyone with a keypair whose address is already in the summary (`SummaryValidPay` returns false for an unknown address). Receiving one dust payment is enough. Submission needs only `NSLORDER`.
- **Impact on a live network:** Supply becomes meaningless. All honest nodes process the order identically, so the mint is confirmed by consensus. Downstream values also wrap, including `(reward + MinerFee) * percent`, which can produce negative rewards.
- **Consensus change:** Yes.
- **Fix:** Reject any `AmmountTrf` or `AmmountFee` above the maximum supply, and check the sum with overflow-safe arithmetic in both `ValidateTrfr` and `SummaryValidPay`. Reject `amount < 0` in `SummaryValidPay` and `CreditTo`. Build releases with range and overflow checks on, after confirming history replays cleanly with them.

### C-06. `CUSTOM` orders mint coins through an unvalidated fee

- **Severity:** CRITICAL. Any funded address can inject an arbitrary miner fee that nothing pays for, without integer overflow. Honest customizations also mint a small amount on every use.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:744-770`, `mpblock.pas:192-203`, `mpblock.pas:262`, `mpblock.pas:333`, `mpblock.pas:352`, `nosounit.pas:494-526`, `mpparser.pas:692`, `mpdisk.pas:678-686`.

`mpprotocol.pas:753-762`
```pascal
Address := GetAddressFromPublicKey(OrderInfo.sender);
if address <> OrderInfo.Address then ErrorCode := 1;
// La direccion no dispone de fondos
if GetAddressBalanceIndexed(Address)-GetAddressPendingPays(Address) < GetCustFee(MyLastBlock) then ErrorCode:=2;
if TranxAlreadyPending(OrderInfo.TrfrID ) then ErrorCode:=3;
if OrderInfo.TimeStamp < LastBlockData.TimeStart then ErrorCode:=4;
if TrxExistsInLastBlock(OrderInfo.TrfrID) then ErrorCode:=5;
if AddressAlreadyCustomized(Address) then ErrorCode:=6;
If AliasAlreadyExists(OrderInfo.Receiver) then ErrorCode:=7;
if not VerifySignedString('Customize this '+Address+' '+OrderInfo.Receiver,OrderInfo.Signature,OrderInfo.sender ) then ErrorCode:=8;
```

`mpblock.pas:192-203`
```pascal
      if ArrayPoolTXs[contador].OrderType='CUSTOM' then
         begin
         OperationAddress := GetAddressFromPublicKey(ArrayPoolTXs[contador].sender);
         if IsCustomizacionValid(OperationAddress,ArrayPoolTXs[contador].Receiver,numero) then
            begin
            minerfee := minerfee+ArrayPoolTXs[contador].AmmountFee;
            ArrayPoolTXs[contador].Block:=numero;
            ArrayPoolTXs[contador].sender:=OperationAddress;
            insert(ArrayPoolTXs[contador],ListaOrdenes,length(listaordenes));
            Inc(BlockTrfrs);
            end;
         end;
```

`nosounit.pas:517-525`
```pascal
  SumPos := GetIndexPosition(Address,ThisRecord);
  if SumPos < 0 then Exit(False);
  if ((ThisRecord.Balance<25000) and (not forceCustom)) then Exit(false);
  if ((thisRecord.Custom<> '') and (not forceCustom)) then Exit(false);
  ThisRecord.Custom:=custom;
  Dec(ThisRecord.Balance,25000);
  ThisRecord.LastOP:=BlockNumber;
  InsBlockRecord(ThisRecord,SumPos);
  Result := true;
```

`mpblock.pas:333-336`
```pascal
      MNsTotalReward := ((GetBlockReward(Numero)+MinerFee)*GetMNsPercentage(Numero,GetCFGDataStr(0))) div 10000;
      if MNsCount>0 then MNsReward := MNsTotalReward div MNsCount
      else MNsReward := 0;
      MNsTotalReward := MNsCount * MNsReward;
```

- **Why it is vulnerable:** `PTC_Custom` never reads `OrderInfo.AmmountFee`. The value comes from the wire and is not covered by the signature, which is only `Customize this <address> <alias>`. `BuildNewBlock` adds that value to `minerfee`, but the sender is charged a fixed 25000 by `IsCustomizacionValid`. `MinerFee` is then split among masternodes, the project address and the miner address, so the difference is created from nothing. A negative fee works too, and pushes reward values negative, which debits recipients through `CreditTo`.
- **Honest-path variant:** `GetCustFee` is 1000000 from block 162000 and clients put that into `AmmountFee` (`mpparser.pas:692`), while only 25000 is deducted. Each honest customization since then has minted 975000 base units. This is small but it is already in history, which matters for a rewrite.
- **Attacker and preconditions:** One funded address with no alias, and a free alias. The check at `mpprotocol.pas:756` needs a balance of at least `GetCustFee`. To profit the attacker also needs a masternode, which H-01 makes cheap. Without one the action is pure inflation. `AddressAlreadyCustomized` limits one address to one alias, but addresses are free to create.
- **Impact on a live network:** Large supply inflation that every node confirms, and direct profit through the masternode share (60% above roughly block 168,000).
- **Consensus change:** Yes.
- **Fix:** Require `AmmountFee` to equal the amount actually charged, and charge exactly `GetCustFee(block)` for new blocks after an activation height. Sign the fee. Reject non-zero `AmmountTrf`. Add a global invariant check that the coins created in a block equal the block reward.

### C-07. Masternode verification can be forged, which diverts the masternode reward stream

- **Severity:** CRITICAL. An unauthenticated peer can decide which masternodes get paid, which is the largest share of each block reward, and can drop all honest masternodes for as long as the attack continues.
- **Status:** Confirmed by reading.
- **Location:** `nosonetwork.pas:716-739`, `mpprotocol.pas:266-271`, `nosomasternodes.pas:507-528`, `nosomasternodes.pas:530-578`, `masterpaskalform.pas:1215-1222`.

`nosonetwork.pas:716-739`
```pascal
Function ValidateMNCheck(Linea:String):string;
var
  CheckData : TMNCheck;
  StartPos : integer;
  ReportInfo : String;
  ErrorCode : integer = 0;
Begin
  Result := '';
  StartPos := Pos('$',Linea);
  ReportInfo := copy (Linea,StartPos,length(Linea));
  CheckData := GetMNCheckFromString(Linea);
  if MnsCheckExists(CheckData.ValidatorIP) then exit;
  if not IsValidator(CheckData.ValidatorIP) then ErrorCode := 1;
  if CheckData.Block <> MyLastBlock then ErrorCode := 2;
  if GetAddressFromPublicKey(CheckData.PubKey)<>CheckData.SignAddress then ErrorCode := 3;
  if not VerifySignedString(CheckData.ValidNodes,CheckData.Signature,CheckData.PubKey) then ErrorCode := 4;
  if ErrorCode = 0 then
    begin
    Result := ReportInfo;
    AddMNCheck(CheckData);
    //if form1.Server.Active then
    //  outGOingMsjsAdd(GetPTCEcn+ReportInfo);
    end
End;
```

`nosomasternodes.pas:514-524`
```pascal
  MinValidations := (GetMNsChecksCount div 2) - 1;
  Resultado := Block.ToString+' ';
  EnterCriticalSection(CSMNsList);
  For counter := 0 to length(MNsList)-1 do
    begin
    if MNsList[counter].Validations>= MinValidations then
      begin
      AddAge := GetMNAgeCount(MNsList[counter]);
      Resultado := Resultado + MNsList[counter].Ip+';'+MNsList[counter].Port.ToString+':'+MNsList[counter].Fund+AddAge+' ';
      end;
    end;
```

`nosomasternodes.pas:538-550`
```pascal
  Procedure AddCheckToIP(IP:String);
  var
    counter2 : integer;
  Begin
  For counter2 := 0 to length(MNsList)-1 do
     begin
     if MNsList[Counter2].Ip = IP then
        begin
        MNsList[Counter2].Validations := MNsList[Counter2].Validations+1;
        Break;
        end;
     end;
  End;
```

- **Why it is vulnerable:** A check claims a `ValidatorIP`, and the code tests only that this IP is a seed. The key that signs is unrelated to that IP: the only test is that the supplied public key hashes to the supplied `SignAddress`. Nothing looks up a registered key for the validator, so any freshly generated key can sign a check "from" any seed.
  - The first check for an IP wins (`MnsCheckExists` at line 727 exits silently), so a forgery sent before block age 500 blocks the real validator. `IsMyMNCheckDone` also makes that validator skip its run (`masterpaskalform.pas:1215`).
  - The signed text is only `ValidNodes`. It omits block number and validator IP, so checks can be reused.
  - `CreditMNVerifications` adds one validation per occurrence without removing duplicates, so one check can list one IP many times.
  - Checks are flooded (`mpprotocol.pas:269`), so one connection reaches the whole network.
- **Attacker and preconditions:** Any peer connected to one node, during the block window. To profit the attacker needs one listed masternode, and H-01 removes the stake requirement for that.
- **Impact on a live network:** Payment of the masternode share only to attacker-chosen entries. Honest masternodes also lose age, and age selects the verificators and the connection targets, so sustained attack also reshapes the node list.
- **Consensus change:** Yes.
- **Fix:** Keep a list of validator public keys, signed by the admin or derived from registered masternodes, and require the check signature to verify under the key registered for that IP. Sign `block number + validator id + ValidNodes`. Count each validator at most once per masternode. Do not let a claim of "exists" pre-empt a later valid signature from the true validator.

### C-08. Auto-update downloads and executes code with no signature or hash

- **Severity:** CRITICAL. This is fleet-wide remote code execution from one point of failure, and it is on by default. The attacker needs a strong position, but nothing cryptographic stands between that position and every node's private keys.
- **Status:** Confirmed by reading that no hash or signature exists. Whether TLS would stop a network attacker is covered in M-02 and is unconfirmed.
- **Location:** `mpred.pas:1038-1069`, `mpparser.pas:1057-1092`, `mpdisk.pas:608-628`, `mpdisk.pas:771-777`, `mpprotocol.pas:998-1007`, `mpprotocol.pas:1031`, `masterpaskalform.pas:633`, `nosogeneral.pas:251-275`.

`mpred.pas:1046-1060`
```pascal
if Uppercase(localOS) = 'WIN' then
   DownLink := 'https://github.com/nosocoin/NosoNode/releases/download/v'+version+'/noso-v'+version+'-x86_64-win64.zip';
if Uppercase(localOS) = 'LINUX' then
   DownLink := 'https://github.com/nosocoin/NosoNode/releases/download/v'+version+'/noso-v'+version+'-x86_64-linux.zip';
MS := TMemoryStream.Create;
Conector := TFPHttpClient.Create(nil);
conector.ConnectTimeout:=1000;
conector.IOTimeout:=1000;
conector.AllowRedirect:=true;
Repeat
Inc(Trys);
   TRY
   Conector.Get(DownLink,MS);
   MS.SaveToFile('NOSODATA'+DirectorySeparator+'UPDATES'+DirectorySeparator+version+'_'+LocalOS+'.zip');
   result := true;
```

`mpparser.pas:1075-1087`
```pascal
if GetLastVerZipFile(Tversion,TArch) then
   begin
   ToLog('console','Version '+Tversion+' downloaded');
   if UnZipUpdateFromRepo(Tversion,TArch) then
     begin
     ToLog('console','Unzipped !');
     {$IFDEF WINDOWS}Trycopyfile('NOSODATA/UPDATES/Noso.exe','nosonew');{$ENDIF}
     {$IFDEF UNIX}Trycopyfile('NOSODATA/UPDATES/Noso','Nosonew');{$ENDIF}
     CreateLauncherFile(true);
     RunExternalProgram(RestartFilename);
     CloseeAppSafely();
     end
   end
```

`mpdisk.pas:771-777`
```pascal
if IncludeUpdate then
   begin
   writeln(archivo,'rm '+AppFileName);
   writeln(archivo,'mv Nosonew Noso');
   writeln(archivo,'chmod +x Noso');
   writeln(archivo,'./Noso');
   end
```

`masterpaskalform.pas:633`
```pascal
  WO_AutoUpdate    : Boolean = true;
```

- **Why it is vulnerable:** The flow is: an `ADMINMSG` directive with an `UPDATE` command, or the operator's `update` command, leads to a download, unzip, a launcher script that replaces the binary, and execution. The admin signature covers only a version string. The binary itself has no pinned hash, no detached signature and no signed manifest. Anything served at that URL runs. `AllowRedirect` is on. `WO_AutoUpdate` defaults to `true`, so nodes update without an operator decision. The update also runs with the node's own rights, which include read access to the unencrypted wallet.
- **Attacker and preconditions:** One of:
  - Control of the `nosocoin` GitHub organization, a maintainer account, or a release asset.
  - A poisoned CI action (M-16).
  - Network interception, if TLS is not verified (M-02).

  The attacker also needs a directive. Holding the admin key is not required, since H-02 lets anyone replay an old `UPDATE` directive for an existing version whose asset was replaced. The README says the repository is archived. If that namespace were ever released, the risk becomes one of repository takeover. The URLs are hard-coded in deployed binaries.
- **Impact on a live network:** Code execution on every auto-updating node within one block interval (the directive delay is `50 + MNsRandomWait*20` seconds), with theft of every wallet key on those machines.
- **Consensus change:** No, but the new verifier must ship through one last unverified update.
- **Fix:** Sign a manifest of version, platform, size and SHA-256 with an offline key separate from the directive key. Embed that public key in the binary, and verify before unzipping. Reject versions lower than the current one. Make auto-update opt-in, or at least delayed. Do not fetch a URL built from a network-supplied version string without validating its format.


## High findings

### H-01. Masternode reports are unauthenticated, and the first report of each block skips every check

- **Severity:** HIGH. A masternode can be listed with no stake and with a forged validation count, and any funded address can be locked by a stranger.
- **Status:** Confirmed by reading.
- **Location:** `nosomasternodes.pas:374-399`, `nosomasternodes.pas:447-476`, `mpblock.pas:312`, `mpblock.pas:338-342`, `mpcoin.pas:66-67`.

`nosomasternodes.pas:374-399`
```pascal
Function IsLegitNewNode(ThisNode:TMNode;block:integer):Boolean;
var
  counter : integer;
Begin
  result := true;
  if GetMNsListLength>0 then
    begin
    EnterCriticalSection(CSMNsList);
    For counter := 0 to length(MNsList)-1 do
      begin
      if ( (ThisNode.Ip = MNsList[counter].Ip) or
           (ThisNode.Sign = MNsList[counter].Sign) or
           (ThisNode.Fund = MNsList[counter].Fund) or
           //(ThisNode.First>MyLastBlock) or
           //(ThisNode.Last>MyLastBlock) or
           //(ThisNode.Total<>0) or
           (GetAddressBalanceIndexed(ThisNode.Fund) < GetStackRequired(block+1)) or
           (ThisNode.Validations<>0) ) then
      begin
        Result := false;
        break;
      end;
    end;
    LeaveCriticalSection(CSMNsList);
  end;
End;
```

`nosomasternodes.pas:462-470`
```pascal
  If Not IsValidIP(ToMNode.Ip) then result := false
  else if ( (ToMNode.Port<0) or (ToMNode.Port>65535) ) then ErrCode := 1
  else if not IsValidHashAddress(ToMNode.Sign) then ErrCode := 2
  else if not IsValidHashAddress(ToMNode.Fund) then ErrCode := 3
  else if ToMNode.first < 0 then ErrCode := 4
  else if ToMNode.last < 0 then ErrCode := 5
  else if ToMNode.total <0 then ErrCode := 6
  else if ToMNode.validations < 0 then ErrCode := 7
  else if ToMNode.hash <> HashMD5String(ToMNode.Ip+IntToStr(ToMNode.Port)+ToMNode.Sign+ToMNode.Fund) then ErrCode := 8;
```

- **Why it is vulnerable:**
  - All checks sit inside `if GetMNsListLength>0`. `ClearMNsList` runs at each block, so the first report after that is accepted with no balance check and no duplicate check. Its `Validations` value also comes straight from the wire, and it is only tested inside the loop, so it can already satisfy `MinValidations` (`nosomasternodes.pas:519`). An honest node reports at block age above `10 + MNsRandomWait`, so an attacker reporting at age 10 is first.
  - The report has no signature. Its `hash` field is an unkeyed MD5 of public fields. Nothing proves control of the `Sign` address, the `Fund` address or the claimed IP.
  - Any paid masternode's `Fund` goes through `AddLockedMM`, and `GetAddressPendingPays` then reserves 10,500 NOSO on that address for 2016 blocks. A stranger can therefore register a victim's address as `Fund` and lock it, about two weeks per payment.
  - The stake test uses a balance at the time of the report. After `MNsLockExpireLapse`, or for addresses not yet paid, the same coins can back different reports in different blocks.
- **Attacker and preconditions:** Any peer. It only has to be first after the block boundary to list an unfunded address.
- **Impact on a live network:** Removes the economic cost of masternodes, which combines with C-07 into theft of the masternode share by an attacker with no stake. The funds lock is also a griefing tool against any large holder.
- **Consensus change:** Yes.
- **Fix:** Move the checks out of the `if`. Require a signature by the fund address over `ip, port, sign address, block`, and bind it to the current block. Force `Validations = 0`, `Total = 0` and sane `First` and `Last` on receipt. Lock only when the fund owner signed.

### H-02. Admin directives have no expiry and can be replayed forever

- **Severity:** HIGH. Any old directive can be replayed by anyone, including `UPDATE` to an old version, `RESTART` and `SETMODE`. Replay gives a route to mass downgrade or restart without the admin key.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:987-1062`, `mpprotocol.pas:264`.

`mpprotocol.pas:1010-1033`
```pascal
msgtime := parameter(TextLine,5);
mensaje := parameter(TextLine,6);
firma := parameter(TextLine,7);
hashmsg := parameter(TextLine,8);
if AnsiContainsStr(MsgsReceived,hashmsg) then errored := true;
mensaje := StringReplace(mensaje,'_',' ',[rfReplaceAll, rfIgnoreCase]);
if not VerifySignedString(msgtime+mensaje,firma,AdminPubKey) then
   begin
   ToLog('events',TimeToStr(now)+'Directive wrong sign');
   errored := true;
   end;
if HashMD5String(msgtime+mensaje+firma) <> Hashmsg then
   begin
   ToLog('events',TimeToStr(now)+'Directive wrong hash');
   errored :=true;
   end;
if not errored then
   begin
   MsgsReceived :=MsgsReceived+hashmsg;
   TCommand := Parameter(mensaje,0);
   TParam   := Parameter(mensaje,1);
   if UpperCase(TCommand) = 'UPDATE' then LaunchDirectiveThread('update '+TParam);
   if UpperCase(TCommand) = 'RESTART' then LaunchDirectiveThread('restart');
   if UpperCase(TCommand) = 'SETMODE' then SetCFGData(TParam,0);
```

- **Why it is vulnerable:** `msgtime` is included in the signature but is never compared with the clock or the block height. The seen list `MsgsReceived` is a typed constant in memory and is empty after every restart. There is no target network or sequence number. `RunUpdate` also has no rule against moving to a lower version: it only skips the exact current version (`mpparser.pas:1070`).
- **Attacker and preconditions:** Any peer holding a past `ADMINMSG` line. These lines were flooded to all nodes, so any former node operator may have them. The node must not have seen that message since its last restart.
- **Impact on a live network:** A replayed `RESTART` takes nodes down at scattered times. A replayed `UPDATE` moves auto-updating nodes to an old release, which can reintroduce fixed bugs or split the network. A replayed `SETMODE` applies an old mode. A replayed `ADDNODE` restores a retired seed, which might now belong to someone else. A replayed `DELNODE` removes a live one.
- **Consensus change:** No for the sequence rule, if all nodes adopt it through a normal release.
- **Fix:** Add a monotonic sequence number, persisted on disk, and an expiry as a block height. Reject anything older. Add a directive-scope prefix to the signed bytes so a directive signature can never be used for anything else. Refuse version downgrades in `RunUpdate` unless the operator asks.

### H-03. One hard-coded admin key is a global root

- **Severity:** HIGH. Compromise of this key means unsigned movement of any balance, freezing of any address, and control of seeds and update triggers. This is a design risk rather than a coding error.
- **Status:** Confirmed by reading.
- **Location:** `masterpaskalform.pas:582-584`, `mpprotocol.pas:1034-1059`, `mpprotocol.pas:975`, `mpblock.pas:217`.

`masterpaskalform.pas:581-584`
```pascal
  {Developer addresses}
  ADMINHash = 'N3DthVsfEUtqrgWFHTEB6F88xLkT3Df';
  AdminPubKey = 'BACo0LC7mWDn53orLANA2zKVSC1HfSe/jc/Ih7+cBQ1oh53Bu2Zo655WFmWnoKHEeaNflb1CR9WcfXuhmkKaY8Y=';
  Authorizedaddresses = 'N3DthVsfEUtqrgWFHTEB6F88xLkT3Df N4ZR3fKhTUod34evnEcDQX3i6XufBDU';
```

`mpprotocol.pas:1054-1059`
```pascal
   if UpperCase(TCommand) = 'ADDLOCKED' then AddCFGData(TParam,5);
   if UpperCase(TCommand) = 'DELLOCKED' then RemoveCFGData(TParam,5);
   if UpperCase(TCommand) = 'ADDNOSOPAY' then AddCFGData(TParam,6);
   if UpperCase(TCommand) = 'DELNOSOPAY' then RemoveCFGData(TParam,6);
   if UpperCase(TCommand) = 'CLEARCFG' then ClearCFGData(TParam);
   if UpperCase(TCommand) = 'RESTORECFG' then RestoreCFGData;
```

- **Why it is vulnerable:** The one key signs directives that freeze addresses (`ADDLOCKED`), trigger unsigned transfers from any address (`ADDNOSOPAY`, executed at `mpblock.pas:233-258`), set the network mode, change seeds and NTP servers, and start updates. GVT transfers also require this key (`mpprotocol.pas:975`). There is no threshold, rotation path or delay. A change of key needs a new binary. No directive is logged in the chain, so a selective directive to some nodes causes a silent split. Directives are not checked for scope either: each carries one signature, covering a free-form string.
- **Attacker and preconditions:** Possession of the private key, or a holder acting against users. Since the project is described as archived in its README, custody of that key is itself an open question.
- **Impact on a live network:** Total. Holders of NOSO must trust one key with their balances, even though they hold their own private keys.
- **Consensus change:** Yes for any removal of `NOSOPAY` or key rotation.
- **Fix:** Remove the power to move funds from directives. Use a threshold scheme for the remaining directives, add an activation delay so users can react, publish directives in the chain, and define key rotation.

### H-04. Consensus is a plurality over 20-bit MD5 values with no quorum

- **Severity:** HIGH. The rule that decides the chain has no minimum agreement and no authentication. A single reachable node can define the network's state for a victim, and the node deletes blocks on that basis.
- **Status:** Confirmed by reading.
- **Location:** `nosoconsensus.pas:215-221`, `nosoconsensus.pas:310-329`, `nosoconsensus.pas:352-357`, `mpred.pas:596-607`, `mpblock.pas:746-760`, `masterpaskalform.pas:1699`.

`nosoconsensus.pas:215-221`
```pascal
Function GetConHash(ILine:String):String;
Begin
  Result := '';
  Result := HashMD5String(Parameter(ILine,2)+copy(Parameter(ILine,5),0,5)+copy(Parameter(ILine,8),0,5)+
                          copy(Parameter(ILine,10),0,5)+copy(Parameter(ILine,17),0,5)+
                          copy(Parameter(ILine,18),0,5)+copy(Parameter(ILine,19),0,5));
End;
```

`nosoconsensus.pas:310-329`
```pascal
  Function GetHighest():string;
  var
    maximum : integer = 0;
    counter : integer;
    MaxIndex : integer = 0;
  Begin
    result := '';
    if length(ArrayCon) > 0 then
      begin
      for counter := 0 to high(ArrayCon) do
        begin
        if ArrayCon[counter].count> maximum then
          begin
          maximum := ArrayCon[counter].count;
          MaxIndex := counter;
          end;
        end;
      result := ArrayCon[MaxIndex].Value;
      end;
  End;
```

`mpred.pas:599-607`
```pascal
ConsenLB := StrToIntDef(GetConsensus(2),-1);
if ( (MyLastBlock > ConsenLB) and (ConsenLB >= 0) ) then
   begin
   Removed := RemoveBlocks(ConsenLB);
   ToLog('console',format('%d blocks deleted',[Removed]));
   UndoneLastBlock;
   //RestartNoso;
   Exit;
   end;
```

`mpblock.pas:751-758`
```pascal
  Repeat
    Last := GetMyLastUpdatedBlock;
    If Last >=  UpToBlock then
      begin
      trydeletefile(BlockDirectory +IntToStr(Last)+'.blk');
      Inc(Result);
      end;
  until Last < UpToBlock;
```

- **Why it is vulnerable:**
  - `GetHighest` takes the top count even if only one node replied. `Css_Percentage` is computed but never used as a threshold in the sync path.
  - `NODESTATUS` is plain text over plain TCP, not signed. An on-path attacker can rewrite any poll, and the poll set is known and small.
  - The vote covers only the first 5 hex characters of most hashes. PSO state and masternode lock state are not in `GetConHash` at all.
  - `SyncWithMainnet` removes local blocks if consensus reports a lower height. The only guard is that the value is not negative, so a forged low value deletes the chain down to that height. It then has only one summary backup, so recovery requires a download, and that download is C-03. A voted height of 0 is worse: `RemoveBlocks` deletes every block file, and because `GetMyLastUpdatedBlock` returns 0 when none remain, the loop's exit condition `Last < UpToBlock` is never met. That spins forever on the GUI thread through the heartbeat, so the node is left with no chain and hung.
  - Polled nodes are only CFG field 1 (nine seeds by default), and `SetNodesArray` runs only at startup and on admin node directives. Masternodes get no vote. Security therefore rests on those seeds, and a few of them going offline shrinks the electorate further. `defseeds.nos` currently lists `38.242.252.153` twice, so duplicated entries in the seed list get two votes (`seednodes.txt` shows the same).
- **Attacker and preconditions:** Control or disruption of enough seeds to hold a plurality among the seeds a victim reaches, or a network position on the victim's path. Blocking most seeds by DoS can be enough, since replies are counted only among nodes that answered.
- **Impact on a live network:** Forced rollbacks, full loss of local blocks with a hung node, chain splits, and acceptance of attacker state by nodes that see a skewed vote. Downstream, any fake consensus value applies to all the checks in `SyncWithMainnet`.
- **Consensus change:** Yes for the vote's content. A minimum quorum on rollback is local hardening.
- **Fix:** Sign status replies by seed keys, require more than half of the configured seeds with a deduplicated list, and vote on full SHA-256 values. Never delete local blocks without a validated replacement chain, add a maximum reorganization depth, and give `RemoveBlocks` a terminating loop.

### H-05. Any peer can corrupt the headers file and drop a node out of sync

- **Severity:** HIGH. One short message from an unauthenticated peer costs a synced node its mempool, its masternode lists and its reward eligibility, and can be repeated.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:1127-1172`, `masterpaskalform.pas:2419-2441`, `mpred.pas:637-641`, `nosonetwork.pas:522-530`.

`mpprotocol.pas:1138-1153`
```pascal
if GetResumenHash =GetConsensus(5) then exit;
startpos := Pos('$',Linea);
Content := Copy(Linea,Startpos+1,Length(linea));
//ToLog('console','Content: '+Linea);
REPEAT
   ThisHeader := Parameter(Content,counter);
   If thisheader<>'' then
      begin
      Inc(TotalReceived);
      ThisHeader := StringReplace(ThisHeader,':',' ',[rfReplaceAll, rfIgnoreCase]);
      Numero := StrToIntDef(Parameter(ThisHeader,0),0);
      blockhash := Parameter(ThisHeader,1);
      sumhash := Parameter(ThisHeader,2);
      LastBlockOnSummary := GetHeadersLastBlock();
      if numero = LastBlockOnSummary+1 then
         AddRecordToHeaders(Numero,blockhash,sumhash)
```

`masterpaskalform.pas:2419-2440`
```pascal
    if Parameter(LLine,0) = 'RESUMENFILE' then
      begin
      MemStream := TMemoryStream.Create;
      DownloadHeaders := true;
        TRY
        AContext.Connection.IOHandler.ReadStream(MemStream);
        GetFileOk := true;
        EXCEPT ON E:EXCEPTION do
          begin
          TryCloseServerConnection(AContext);
          GetFileOk := false;
          end;
        END; {TRY}
      if GetfileOk then
        begin
        if SaveStreamAsHeaders(MemStream) then
          ToLog('console',Format(rs0047,[copy(HashMD5File(ResumenFilename),1,5)]));//'Headers file received'
        end;
      UpdateMyData();
      LastTimeRequestResumen := 0;
      DownloadHeaders := false;
      MemStream.Free;
```

`mpred.pas:637-641`
```pascal
if Copy(GetResumenhash,0,5) <> GetConsensus(cHeaders) then  // Request headers
   begin
   ClearAllPending;
   ClearMNsChecks();
   ClearMNsList();
```

- **Why it is vulnerable:** `HEADUPDATE` is handled whether or not it was requested. The early exit at line 1138 compares a full hash with a 5-character value, so it is never true. Each record is appended if its number is the next one, with no check of its hash fields. `RESUMENFILE` replaces the whole headers file with arbitrary bytes on inbound connections. After either one, the node's headers hash differs from consensus, and `SyncWithMainnet` clears pending orders, masternode checks and the masternode list on each pass until repaired. Meanwhile `IsAllSynced` is non-zero, so `GetVerificationMNLine` answers `False` and a masternode fails verification.
- **Attacker and preconditions:** Any peer that has passed the handshake, or that the victim connects to.
- **Impact on a live network:** Targeted removal of a masternode from the paid list, loss of pending transactions on the victim, and a sync request from a possibly malicious peer. Hitting seeds periodically can destabilize the network as a whole.
- **Consensus change:** No.
- **Fix:** Accept headers only as a reply to a request. Stage them, and replace the local file only if the full result matches. Check each record against the local block hash when the block exists. Do not wipe the mempool on a headers mismatch alone.

### H-06. `MNFILE` and `PSOSFILE` overwrite masternode state with no authorization

- **Severity:** HIGH. Unsolicited messages can rewrite the masternode list and ages (on a 20-bit check) and the locked-stake table (with no check at all), which feed node selection and spend validation. One small `PSOSFILE` from any inbound peer can also tie up the node, and a forged file then blocks every later start until an operator deletes it.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:1108-1124`, `masterpaskalform.pas:2584-2600`, `nosonetwork.pas:1227-1242`, `nosomasternodes.pas:848-912`, `nosopsos.pas:138-203`, `nosonetwork.pas:1435`, `mpdisk.pas:162`.

`mpprotocol.pas:1108-1118`
```pascal
Procedure PTC_ProcessMNFileIncoming(LText:String);
var
  MNText: String;
Begin
  MNText := ExtractMNsText(LText);
  if copy(HashMD5String(MNText+#13#10),1,5) = GetConsensus(8) then
    begin
    //ToLog('console','Received MNs hash match!');
    SaveMNsFile(MNText);
    FillNodeList;
    end
```

`masterpaskalform.pas:2584-2600`
```pascal
      else if parameter(LLine,0) = 'PSOSFILE' then
        begin
        DownloadPSOs := true;
        MemStream := TMemoryStream.Create;
        if GetStreamFromContext(Acontext,MemStream) then
          begin
          if SavePSOsToFile(MemStream) then
            begin
            LoadPSOFileFromDisk;
            UpdateMyData();
            ToLog('console','PSOs file received on server');
            end;
          end;
        MemStream.Free;
        DownloadPSOs := false;
        LasTimePSOsRequest := 0;
        end
```

`nosopsos.pas:165-172`
```pascal
      SetPSOHeaders(NewHeader);
      TRY
        for counter := 0 to NewHeader.MNsLock-1 do
        begin
        MNData := Default(TMNsLock);
        MyStream.Read(MNData,sizeof(MNData));
        InsertLockedMN(MNData);
        end;
```

`mpdisk.pas:162`
```pascal
LoadPSOFileFromDisk;
```

- **Why it is vulnerable:**
  - `MNFILE` content is accepted if a 20-bit MD5 prefix matches, and it can be sent unasked. The text goes through `FillMNsArray` and `FillNodeList`, so it controls outbound connection targets (the verificators) and the ages used to compute the next masternode file. As with C-01, the unchanged prefix hides the forgery from the sync logic.
  - `PSOSFILE` is written with no hash check at all, then loaded. `MNSLockArray` supplies the `IsLockedMN` value used in spend validation. The PSO hash is not in `GetConHash`, so a mismatch does not change a node's vote.
  - `LoadPSOFileFromDisk` trusts the file's 12-byte header. The lock count is unchecked, and `Read` does not raise at end of stream, so a large count keeps inserting empty records, each insert copying a growing array. On the server path this ties up one Indy thread and contends for `CS_LockedMNs`, which `GetAddressPendingPays` needs. The file is already saved by then, so `VerifyFiles` reloads it on the main thread at every start, and the node does not finish starting. The cost is quadratic, so this is an effective hang rather than an immediate crash.
- **Attacker and preconditions:** Any peer past the handshake for inbound messages. `PSOSFILE` is also accepted on outbound connections. An MNFILE forgery needs about a million MD5 attempts per consensus value.
- **Impact on a live network:** A persistent denial of service against any reachable node, which recovers only when an operator removes `psos.dat`. Eclipse of a node through forged connection targets, which leads to C-03. Release of locked stake or freezing of any address on the affected node, which makes that node's mempool differ from others and so makes its next block different. Age data forged on many nodes changes the verificator set.
- **Consensus change:** No for rejecting unsolicited or unmatched data. Strong proof needs a signed or block-committed value, which is a protocol change.
- **Fix:** Accept these files only on request, and compare a full hash. Check the file size against header counts before loading. Derive the masternode list and lock table from chain data rather than sidecar files. Include them in the voted state.

### H-07. Signed text omits fields and has no field separators

- **Severity:** HIGH. A relay can change a transfer's payment reference and type, and can shift value between amount and fee, while the signature stays valid.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:792-794`, `mpprotocol.pas:93-121`, `mpcoin.pas:297-298`, `mpprotocol.pas:883-915`.

`mpprotocol.pas:792-795`
```pascal
else if not VerifySignedString(IntToStr(order.TimeStamp)+origen+order.Receiver+IntToStr(order.AmmountTrf)+
   IntToStr(order.AmmountFee)+IntToStr(order.TrxLine),
   Order.Signature,Order.sender ) then
   result:=6
```

`mpprotocol.pas:101-113`
```pascal
    ThisData.OrderID    := Parameter(textline,1);
    ThisData.OrderLines := StrToInt(Parameter(textline,2));
    ThisData.OrderType  := Parameter(textline,3);
    ThisData.TimeStamp  := StrToInt64(Parameter(textline,4));
    ThisData.reference  := Parameter(textline,5);
    ThisData.TrxLine    := StrToInt(Parameter(textline,6));
    ThisData.sender     := Parameter(textline,7);
    ThisData.Address    := Parameter(textline,8);
    ThisData.Receiver   := Parameter(textline,9);
    ThisData.AmmountFee := StrToInt64(Parameter(textline,10));
    ThisData.AmmountTrf := StrToInt64(Parameter(textline,11));
    ThisData.Signature  := Parameter(textline,12);
    ThisData.TrfrID     := Parameter(textline,13);
```

- **Why it is vulnerable:**
  - `Reference`, `OrderType`, `OrderLines` and `OrderID` are not in the signed text, and C-04 means `TrfrID` does not bind them either.
  - `amount`, `fee` and `line` are concatenated as decimal digits with no separator. The same digit string can be split differently, subject to no leading zeros in each part. A relay can therefore rewrite an order to have a different amount and fee and keep the same signature, as long as the minimum-fee rule still holds.
  - `TrxLine` is not checked against the line's actual position.
  - There is no domain tag. Separation between message types exists only because each format happens to start differently.
- **Attacker and preconditions:** Any node or relay that handles the order, racing the original. Orders flood, so a modified copy with its own `TrfrID` competes with, or adds to, the original.
- **Impact on a live network:** Payment references are commonly used by exchanges and services to attribute deposits. A changed reference can credit the wrong account. Re-splitting changes the amount delivered. Retyping an order as `CUSTOM` turns a payment into an alias assignment (M-01).
- **Consensus change:** Yes.
- **Fix:** Sign a canonical encoding: a domain tag, a chain ID, and length-prefixed fixed-order fields including order type, reference and order ID. Hash with SHA-256. Verify line numbers.

### H-08. The signed bytes pass through a lenient Base64 decoder

- **Severity:** HIGH if confirmed. Every signature in the system signs a filtered form of its message, so different messages can share one signature. That undermines admin directives, masternode checks and customizations. It rates lower if the FPC behaviour differs from what is described here.
- **Status:** Suspected. The call is confirmed by reading. The filtering behaviour depends on FPC `base64` unit behaviour, which is not in the tree and was not executed. `DecodeStringBase64` is recalled to default to `strict = false`, which ignores characters outside the Base64 alphabet.
- **Location:** `nosocrypto.pas:217-242`.

`nosocrypto.pas:231-242`
```pascal
Function VerifySignedString(StringToVerify,B64String,PublicKey:String):boolean;
var
  Signature, MessageAsBytes: TBytes;
Begin
  result := false;
  TRY
  MessageAsBytes := StrToByte(DecodeStringBase64(StringToVerify));
  Signature := StrToByte(DecodeStringBase64(B64String));
  Result := TSignerUtils.VerifySignature(Signature, MessageAsBytes,StrToByte(DecodeStringBase64(PublicKey)), TKeyType.SECP256K1);
  EXCEPT Exit;
  END{Try};
End;
```

- **Why it is vulnerable:** `StringToVerify` is free text, not Base64, yet it is decoded before hashing. If non-alphabet characters are dropped, then spaces, dots, colons, semicolons and similar characters are not signed. The effects:
  - `update 0.4.4Ab9` and a variant with the dots in other places would share a signature.
  - `ADDNODE` text that differs only in dot positions could turn one IP into another with the same digits.
  - In `$MNCHECK`, `ValidNodes` is made of `.`, `;` and `:` separated numbers, so the same digits in other positions verify too, which can name a different set of IPs.
  - `ADMINMSG` hash checks do not help, because `hashmsg` is an unkeyed MD5 that any party can recompute.

  Also, trailing characters that do not fill a 4-character Base64 group may contribute few or no signed bits. For a transfer this tail is the low digits of the fee plus the line number, so it may be unsigned on some message lengths.
- **Attacker and preconditions:** Any party that sees a signed message.
- **Impact on a live network:** If confirmed, a legitimate past directive could be adapted, not merely replayed, without the admin key.
- **Consensus change:** Yes, and any compatible implementation must copy the exact decoder behaviour. See the Go rewrite notes.
- **Fix:** Hash the raw message bytes. To confirm, run one offline test vector through a built node: sign `update 0.4.4` and verify `update 0.44`, and compare the output of `DecodeStringBase64` with its strict form.

### H-09. RPC has no authentication, can be reached from a browser, and spends the wallet

- **Severity:** HIGH. RPC is off by default, so this affects those who enable it. For them, any request that passes the IP filter can spend the wallet and obtain private keys.
- **Status:** Confirmed by reading. Browser reachability depends on the browser's private-network policy.
- **Location:** `masterpaskalform.pas:2274-2305`, `mprpc.pas:446-501`, `mprpc.pas:859-878`, `mprpc.pas:947-974`, `masterpaskalform.pas:623-624`, `mprpc.pas:86-93`.

`masterpaskalform.pas:2281-2293`
```pascal
if ( (RPCFilter) and (Not ValidRPCHost(ARequestInfo.RemoteIP)) ) then
   begin
   AResponseInfo.ContentText:= GetJSONErrorCode(498,-1);
   end
else if ARequestInfo.Command <> 'POST' then
   begin
   AResponseInfo.ContentText:= GetJSONErrorCode(400,-1);
   end
else if ARequestInfo.Command = 'POST' then
   begin  // Is a post request
   StreamString := TStringStream.Create('', TEncoding.UTF8);
   TRY
   StreamString.LoadFromStream(ARequestInfo.PostStream);
```

`mprpc.pas:859-878`
```pascal
function RPC_NewAddressFull(NosoPParams:string):string;
var
  counter : integer;
  NewAddress : WalletData;
  PubKey,PriKey : string;
Begin
  BeginPerformance('RPC_NewAddressFull');
  result := 'newaddressfull'#127;
  NewAddress := Default(WalletData);
  NewAddress.Hash:=GenerateNewAddress(PubKey,PriKey);
  NewAddress.PublicKey:=pubkey;
  NewAddress.PrivateKey:=PriKey;
  InsertToWallArr(NewAddress);
  if RPCSaveNew then SaveAddresstoFile(RPCBakDirectory+NewAddress.Hash+'.pkw',NewAddress);
  Result := result+NewAddress.Hash+#127+NewAddress.PublicKey+#127+NewAddress.PrivateKey;
  trim(result);
  S_Wallet := true;
  U_DirPanel := true;
  EndPerformance('RPC_NewAddressFull');
End;
```

- **Why it is vulnerable:** `RPCPass` is stored, displayed and saved, but it is never compared with anything, as a search for the name shows. The default is the literal `default`, which gives operators a false impression of protection. The only control is the `RemoteIP` filter, which can be disabled, and the server binds every interface because `Bindings` is cleared. No `Origin`, `Host` or content-type check exists. A web page visited on the node's machine can send a simple cross-site `POST` with a `text/plain` body to `127.0.0.1:8078`. The remote address is then loopback and the filter passes, and although the page cannot read the reply, `sendfunds` needs no reply. `getnewaddressfull` returns a private key in the response, and `restart` and `setdefault` are also exposed.
- **Attacker and preconditions:** RPC enabled. Then one of: a malicious page visited on that host, a local user, a host in the whitelist, or any network host if the filter is off.
- **Impact on a live network:** Loss of funds on exchange, pool and service nodes, which are the deployments most likely to use RPC.
- **Consensus change:** No.
- **Fix:** Require a strong random token, generated at install and compared in constant time. Bind to loopback by default. Reject requests that carry an `Origin` header, or check it, and require `Content-Type: application/json`. Separate read and spend scopes. Never return private keys over RPC by default.

### H-10. Private keys are stored in clear and can reach logs and a plain-text crash report

- **Severity:** HIGH. Any read access to a node's files gives direct theft, and the logging path can move keys off the machine.
- **Status:** Confirmed by reading.
- **Location:** `nosowallcon.pas:18-27`, `nosowallcon.pas:278-306`, `mpparser.pas:193`, `mpparser.pas:1471-1488`, `masterpaskalform.pas:1657`, `masterpaskalform.pas:1671-1673`, `nosogeneral.pas:535-562`, `mpparser.pas:1186-1192`.

`nosowallcon.pas:18-27`
```pascal
  WalletData = Packed Record
    Hash : String[40];        // El hash publico o direccion
    Custom : String[40];      // En caso de que la direccion este personalizada
    PublicKey : String[255];  // clave publica
    PrivateKey : String[255]; // clave privada
    Balance : int64;          // el ultimo saldo conocido de la direccion
    Pending : int64;          // el ultimo saldo de pagos pendientes
    Score : int64;            // estado del registro de la direccion.
    LastOP : int64;           // tiempo de la ultima operacion en UnixTime.
    end;
```

`mpparser.pas:193`
```pascal
if not AnsiContainsStr(HideCommands,Uppercase(command)) then ToLog('Console','>> '+Linetext);
```

`masterpaskalform.pas:1671-1673`
```pascal
  if ( (not fileExists(ClosedAppFilename)) and (WO_Sendreport) ) then
    begin
    if SEndFileViaTCP(ResumeLogFilename,'REPORT','debuglogs.nosocoin.com',18081) then
```

- **Why it is vulnerable:**
  - `WalletData` is written as raw records. Private keys sit in Base64 in `wallet.pkw`, `wallet.pkw.bak`, every `RPC/*.pkw` backup and `tempwallet.pkw`, with default file permissions and no passphrase.
  - `ParseCommandLine` logs each command line, including `newfromkeys <public> <private>`. `showkeys` writes the private key to the console log. The console log goes to `NOSODATA/LOGS/console.txt`.
  - `MixTxtFiles` merges these logs into `report.txt` at startup. If `WO_SendReport` is on and the last session did not close cleanly, the file is sent by raw TCP with no TLS to `debuglogs.nosocoin.com:18081`. `WO_SendReport` defaults to false.
  - `expkeys` places keys on the system clipboard.
  - C-02 makes `wallet.pkw` writable remotely, and any file read issue exposes it.
- **Attacker and preconditions:** Local read access, backup access or malware. For the report path, an on-path observer or the owner of that hostname, with a user who opted in and used those commands.
- **Impact on a live network:** Direct theft from individual nodes. A masternode's keys are online by design, so the exposure is permanent on those hosts.
- **Consensus change:** No.
- **Fix:** Encrypt wallets with a passphrase-derived key (Argon2id or scrypt plus an AEAD). Set mode 0600. Redact commands that carry key material before logging, and never log the output of key commands. Send reports only over verified TLS, after showing the user the content.

### H-11. File-transfer handlers let a peer stall sync and allocate memory on its own terms

- **Severity:** HIGH. One idle TCP connection can disable part of a node's sync machinery with no time limit. This chains with H-05, which forces a resync that can then never complete.
- **Status:** Confirmed by reading of the node and vendored Indy. Actual memory effect depends on the allocator and operating system.
- **Location:** `masterpaskalform.pas:2422-2424`, `masterpaskalform.pas:2447-2449`, `mpred.pas:451`, `mpred.pas:642`, `mpred.pas:671`, `nosonetwork.pas:1144`, `nosogeneral.pas:387`.

`masterpaskalform.pas:2446-2450`
```pascal
     MemStream := TMemoryStream.Create;
     DownLoadBlocks := true;
       TRY
       AContext.Connection.IOHandler.ReadStream(MemStream);
       MemStream.SaveToFile(BlockZipName);
```

`mpred.pas:445-451`
```pascal
     if ( (UTCTime > StrToInt64Def(GetConexIndex(contador).lastping,0)+15) and
        (not GetConexIndex(contador).IsBusy) and (not REbuildingSumary) )then
        begin
        ToLog('events',TimeToStr(now)+'Conection closed: Time Out Auth -> '+GetConexIndex(contador).ip);   //Conection closed: Time Out Auth ->
        CloseSlot(contador);
        end;
     if GetConexIndex(contador).IsBusy then SetConexIndexLastPing(contador,UTCTimeStr);
```

`Packages/Indy10.zip -> Indy10/Core/IdIOHandler.pas:2026-2056`
```pascal
  if (AByteCount = cSizeUnknown) and (not AReadUntilDisconnect) then begin
    // Read size from connection
    if LargeStream then begin
      {$IFDEF STREAM_SIZE_64}
      LByteCount := ReadInt64;
      {$ELSE}
      // TODO: if the peer is sending more than 2GB of data, don't fail
      // here, just read it all in a loop until finished...
      LTmp := ReadInt64;
      if LTmp > MaxInt then begin
        raise EIdIOHandlerStreamDataTooLarge.Create(RSDataTooLarge);
      end;
      LByteCount := TIdStreamSize(LTmp);
      {$ENDIF}
    end else begin
      LByteCount := ReadInt32;
    end;
  end else begin
    LByteCount := AByteCount;
  end;

  // Presize stream if we know the size - this reduces memory/disk allocations to one time.
  // TODO: need to add an option for this. user might not want to presize here, eg for reading
  // int64 files, or when filling a manually-sized file using multiple threads.
  if (AStream <> nil) and (LByteCount > -1) then begin
    LPos := AStream.Position;
    if (High(TIdStreamSize) - LPos) < LByteCount then begin
      raise EIdIOHandlerStreamDataTooLarge.Create(RSDataTooLarge);
    end;
    AdjustStreamSize(AStream, LPos + LByteCount);
  end;
```

- **Why it is vulnerable:**
  - `ReadStream` takes a 32-bit size from the peer and presizes the memory stream with it before any data has arrived. Limit: about 2 GiB per stream.
  - Server-side connections set no `ReadTimeout`, so Indy treats the default as infinite (`Packages/Indy10.zip -> Indy10/Core/IdIOHandler.pas:1676-1679`). A peer can announce a size and go silent.
  - During this time the global flags `DownLoadBlocks`, `DownloadHeaders` or `DownloadPSOs` stay true, and `SyncWithMainnet` will not request that data from anyone (`mpred.pas:642`, `mpred.pas:671`).
  - `IsBusy` stays true, and `LeerLineasDeClientes` then refreshes `lastping` itself, so the idle-peer timeout never fires. The slot stays held.
  - On outbound connections `MaxLineLength := Maxint` disables the 16 KiB line limit, so a peer can grow a line until memory runs out, subject to the 10-second read timeout between chunks. `RequestLineToPeer` does the same for consensus polls.
- **Attacker and preconditions:** Any peer past the handshake. One connection per IP, since duplicates are banned, but 99 slots can be filled from 99 addresses.
- **Impact on a live network:** A node that cannot resync stops following the chain and fails verification, and the slot-filling variant blocks honest peers. Against seeds it degrades the network.
- **Consensus change:** No.
- **Fix:** Set hard read deadlines on every server connection. Pass a fixed maximum for each file type to `ReadStream` and refuse larger sizes. Do not presize from an unauthenticated value. Hold download state per connection, and clear it with `try..finally`. Keep the default line limit.


## Medium findings

### M-01. Alias rules are enforced only by the sender's client, and order type is not checked

- **Severity:** MEDIUM. Aliases can collide or be misleading, which can redirect payments addressed by alias. Direct address payments are not affected.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:744-770`, `mpprotocol.pas:802`, `mpblock.pas:192-203`, `nosounit.pas:494-526`, `mpparser.pas:642-675`, `mpparser.pas:735-743`.

`mpprotocol.pas:802-803`
```pascal
else if ( (order.OrderType='TRFR') and  (Not IsValidHashAddress(Order.Receiver)) ) then
   result := 10
```

`nosounit.pas:503-513`
```pascal
    For counter := 0 to high(BlockRecords) do
      begin
      if BlockRecords[counter].VRecord.Hash=Address then
        begin
        if ((BlockRecords[counter].VRecord.Custom<> '') and (not forceCustom)) then exit(false);
        if ((BlockRecords[counter].VRecord.Balance<25000) and (not forceCustom)) then Exit(false);
        BlockRecords[counter].VRecord.Custom := custom;
        Dec(BlockRecords[counter].VRecord.Balance,25000);
        exit(true);
        end;
      end;
```

- **Why it is vulnerable:** Length, character set and "alias must not be an address" are checked only in `CustomizeAddress`, on the sender's own machine. `PTC_Custom` checks none of them. `PTC_Order` accepts any `OrderType`, and `ValidateTrfr` only validates the receiver when the type is `TRFR`. An order with type `CUSTOM` therefore bypasses `AliasAlreadyExists` and `AddressAlreadyCustomized`. Block building checks neither of those either, so two addresses can hold the same alias. Lookup returns the first indexed record, which is the lowest disk position, so an older attacker address can take an existing alias. In addition, `UpdateSummaryChanges` adds index entries only for new records (`nosounit.pas:541-545`), so an alias set on an existing address is not found by `AliasAlreadyExists` until the index is rebuilt. Nodes that rebuilt at different times can then disagree about whether an alias is taken.
- **Attacker and preconditions:** Holder of an address with no alias and with enough balance.
- **Impact on a live network:** Payments sent to an alias can reach the wrong address. Duplicate aliases are also a state a compatible implementation must reproduce.
- **Consensus change:** Yes.
- **Fix:** Validate the type in `PTC_Order` (only `TRFR`). Validate alias format and uniqueness in `PTC_Custom` and in block building.

### M-02. TLS verification is not requested, and bootstrap trust is thin

- **Severity:** MEDIUM. If certificates are not verified, a network attacker gains the update and seed channels, which raises the practical risk of C-08 considerably.
- **Status:** Suspected for verification. The code never sets `VerifySSLCertificate`. Whether `TFPHTTPClient` verifies by default depends on the FPC version, which is not in the tree. The rest is confirmed by reading.
- **Location:** `mpred.pas:992-996`, `mpred.pas:1051-1058`, `nosogeneral.pas:418-432`, `nosonosocfg.pas:77-91`, `mpparser.pas:268-272`, `ssl/`.

`nosonosocfg.pas:77-91`
```pascal
  if not fileexists(CFGFilename) then
    begin
    SaveCFGToFile(DefaultNosoCFG);
    GetCFGFromFile;
    Defseeds := SendApiRequest('https://raw.githubusercontent.com/nosocoin/NosoNode/main/defseeds.nos');
    if defseeds <> '' then
      begin
      SetCFGData(Defseeds,1);
      Tolog('console','Defaults seeds downloaded from trustable source');
      end
    else
      begin
      ToLog('console','Unable to download default seeds. Please, use a fallback');
      end;
    end;
```

`mpred.pas:1051-1058`
```pascal
Conector := TFPHttpClient.Create(nil);
conector.ConnectTimeout:=1000;
conector.IOTimeout:=1000;
conector.AllowRedirect:=true;
Repeat
Inc(Trys);
   TRY
   Conector.Get(DownLink,MS);
```

- **Why it is vulnerable:** No HTTPS client in the node sets certificate options, so the outcome rests on library defaults. On Windows, the node uses `libeay32.dll` and `ssleay32.dll`. The tree ships OpenSSL 1.0.2u, a branch that reached end of life in 2019. Seeds fetched on a new install overwrite CFG field 1 with whatever the URL returns, without a signature, and the code logs that as coming from a "trustable source". Everything else on the network, peer and RPC traffic included, is cleartext TCP.
- **Attacker and preconditions:** On-path network attacker for the TLS case. Control of the repository for the seed file.
- **Impact on a live network:** New nodes join the attacker's network, and an update swap becomes possible.
- **Consensus change:** No.
- **Fix:** Set `VerifySSLCertificate := True` with a pinned CA bundle, confirm on each platform, and update OpenSSL. Sign `defseeds.nos` and `lastrelease.txt` with the release key, and treat them as advisory.

### M-03. Block timing depends on one unauthenticated NTP reply

- **Severity:** MEDIUM. Block boundaries and message windows are driven by local time, and that time can be shifted for a target with no bound.
- **Status:** Confirmed by reading.
- **Location:** `nosotime.pas:92-118`, `masterpaskalform.pas:2066-2067`, `masterpaskalform.pas:1681`.

`nosotime.pas:103-117`
```pascal
Rannumber := Random(length(MyArray));
For Counter := 0 to length(MyArray)-1 do
   begin
   ThisNTP := GetNetworkTimestamp(MyArray[Rannumber]);
   if ThisNTP>0 then
      begin
      Result := ThisNTP - DateTimeToUnix(Now);
      NosoT_LastServer := MyArray[Rannumber];
      NosoT_LastUpdate := UTCTime;
      break;
      end;
   Inc(RanNumber);
   If RanNumber >= length(MyArray)-1 then RanNumber := 0;
   end;
NosoT_TimeOffset := Result;
```

- **Why it is vulnerable:** The first server that answers sets the offset. There is no sanity bound, median, or authentication, and UDP NTP is spoofable. The server list comes from CFG field 2, so C-01 can substitute it. All of `BlockAge`, `NextBlockTimeStamp`, the 5-second handshake time check, and order timestamp limits come from this value.
- **Attacker and preconditions:** On-path attacker, or an attacker who controls a listed NTP host, or C-01.
- **Impact on a live network:** A shifted node misses block slots, builds at the wrong time, and refuses or is refused by peers. A shifted seed loses its vote value.
- **Consensus change:** No.
- **Fix:** Query several servers, take the median, reject a change beyond a small limit, and cross-check with peer time.

### M-04. Peers decide what a node believes its own IP is

- **Severity:** MEDIUM. A peer can take a masternode out of the paid list and can block a chosen inbound peer.
- **Status:** Confirmed by reading.
- **Location:** `masterpaskalform.pas:1224-1235`, `masterpaskalform.pas:2783`, `masterpaskalform.pas:2821`, `mpred.pas:1084-1105`.

`masterpaskalform.pas:1224-1235`
```pascal
    if ( (BlockAge > 10) and (LastIPVerify<UTCtime) ) then
      begin
      LastIPVerify := NextBlockTimeStamp;
      MyIP := GetMiIP();
      //ToLog('console','Auto IP executed');
      if  ( (MyIP <> '') and (MyIP <> LocalMN_IP) and (MyIP <> 'Closing NODE') and (MyIP <> 'BANNED') and (IsValidIP(MyIP))) then
        begin
        ToLog('console','Auto IP: updated to '+MyIp);
        LocalMN_IP := MyIP;
        S_AdvOpt := true;
        end;
      end;
```

`masterpaskalform.pas:2821`
```pascal
         if IsValidIP(MiIp) then MyPublicIP := MiIp;
```

- **Why it is vulnerable:** Each block, the masternode thread asks one random node for its IP and overwrites `LocalMN_IP`, and saves it. The `MN_AutoIP` option is not consulted here, so this also runs on nodes configured with a static IP. A single reply decides the result. Separately, `MyPublicIP` is set from the first field of any peer's handshake line, and any later connection from that IP is dropped as "Own connected" at line 2783.
- **Attacker and preconditions:** A node listed in `NodesList` for `GETMIIP`. Any handshake for `MyPublicIP`, although honest peers overwrite the value on their next connection.
- **Impact on a live network:** A masternode reports the wrong IP and fails verification until corrected. `IsValidator(LocalMN_IP)` can also change, so a seed may stop validating.
- **Consensus change:** No.
- **Fix:** Honor `MN_AutoIP`, require agreement from several nodes, and never change a configured static IP. Do not set `MyPublicIP` from peer input.

### M-05. Masternode verification does not prove a working node or control of the claimed IP

- **Severity:** MEDIUM. Rewards can go to entries that do no work, or to an attacker who names another operator's server.
- **Status:** Confirmed by reading.
- **Location:** `nosomasternodes.pas:205-224`, `nosonetwork.pas:522-530`, `nosonetwork.pas:546-556`.

`nosomasternodes.pas:218-224`
```pascal
      WasPositive := StrToBoolDef(Parameter(Linea,0),false);
      if ( (WasPositive) and (Parameter(Linea,1)=CurrSynctus) ) then
        begin
        EnterCriticalSection(CSVerNodes);
        VerifiedNodes := VerifiedNodes+Ip+';'+Port.ToString+':';
        LeaveCriticalSection(CSVerNodes);
        end
```

- **Why it is vulnerable:** The verifier accepts a positive reply when field 1 equals `CurrSynctus`, which is the block number plus short hash prefixes, all public. It does not check that the reply is bound to the listed `Sign` or `Fund`. A small responder passes without running a node. Also, a third party can list a victim's IP and port with its own `Fund`. The victim then answers honestly, the check passes, and the reward goes to the third party. `IsIPMNAlreadyProcessed` then blocks the victim's own later report for that block.
- **Attacker and preconditions:** One listing, which needs stake unless H-01 applies.
- **Impact on a live network:** Reward capture and weakening of the service that masternodes are paid for.
- **Consensus change:** Yes.
- **Fix:** Use a signed challenge-response from the verifier, with a random nonce, signed by the listed `Sign` key, and bind `Sign` to `Fund` in a signed report.

### M-06. Data races on shared state, some leading to out-of-bounds reads

- **Severity:** MEDIUM. Races are reachable from unauthenticated requests during block building. Effects range from wrong answers to access violations, and thread death in some cases.
- **Status:** Confirmed by reading for the unsynchronized access. Reachable effects are suspected, because nothing was run.
- **Location:** `nosounit.pas:331-335`, `nosounit.pas:539-545`, `mpcoin.pas:77-88`, `mpcoin.pas:224-226`, `masterpaskalform.pas:1272-1274`, `mpred.pas:466-468`, `nosonetwork.pas:656-661`, `nosoconsensus.pas:335-352`, `mpprotocol.pas:842-948`.

`mpcoin.pas:77-88`
```pascal
if GetPendingCount>0 then
   begin
   EnterCriticalSection(CSPending);
   SetLength(CopyPendings,0);
   CopyPendings := copy(ArrayPoolTXs,0,length(ArrayPoolTXs));
   LeaveCriticalSection(CSPending);
   for cont := 0 to length(CopyPendings)-1 do
      begin
      if address = ArrayPoolTXs[cont].receiver then
         result := result+ArrayPoolTXs[cont].AmmountTrf;
      end;
   end;
```

`nosounit.pas:539-545`
```pascal
      For counter := 0 to high(BlockRecords) do
        begin
        if BlockRecords[counter].DiskSlot <0 then
          begin
          BlockRecords[counter].DiskSlot := FileSize(SumFile) div Sizeof(TSummaryData);
          InsertIndexData(BlockRecords[counter].VRecord,BlockRecords[counter].DiskSlot);
          end;
```

- **Why it is vulnerable:**
  - `GetAddressIncomingpays` copies the pending array, then loops over the copy's length but reads the live array with no lock. Block building empties the live array, so the loop reads out of bounds, unchecked in Release. It is reachable through RPC `getaddressbalance`.
  - `UpdateSummaryChanges` calls `InsertIndexData` without `CS_SumIndex`, while readers such as `NSLBALANCE` walk the same dynamic arrays. An `Insert` can reallocate under them.
  - `GetIndexPosition` reads `SumaryIndex[IndexPos]` before it takes the lock, and `CreateSumaryIndex` can shrink the array at that moment.
  - `AddressAlreadyCustomized` and `GVTAlreadyTransfered` index the pool with no lock.
  - `TCryptoThread.Execute` reads `ArrayCriptoOp[0]` with no lock, while `VerifyConnectionStatus` can set it to zero length. That code is outside any `TRY`, so the crypto thread can die silently.
  - `CloseSlot` uses a saved `TIdContext` that Indy may already have freed.
  - `PTC_Order` runs on the crypto thread and on Indy threads for `NSLORDER`. Balance check and pool insert are separate steps, so two spends can pass concurrently. The block builder still enforces balance, so this affects the mempool only.
- **Attacker and preconditions:** Any client sending the matching request around a block boundary.
- **Impact on a live network:** Node instability. A dead crypto thread stops all order processing on that node with no alarm.
- **Consensus change:** No.
- **Fix:** Use one state lock, or copy-on-read snapshots. Use `try..finally` around each lock. Wrap thread bodies, and restart or alert on failure. Replace saved contexts with a lookup under a lock.

### M-07. Expensive work runs on the main thread with no per-peer budget

- **Severity:** MEDIUM. A peer can delay the same thread that builds blocks.
- **Status:** Confirmed by reading. Throughput effect is not measured.
- **Location:** `mpprotocol.pas:208-212`, `mpprotocol.pas:264-271`, `masterpaskalform.pas:2036-2056`, `nosonetwork.pas:1334-1339`.

`mpprotocol.pas:264-271`
```pascal
      else if UpperCase(LineComando) = 'ADMINMSG' then PTC_AdminMSG(ProcessLine)
      else if UpperCase(LineComando) = '$MNREPO' then AddWaitingMNs(ProcessLine)//
      else if UpperCase(LineComando) = '$MNCHECK' then
         begin
         ValidMNCheck := ValidateMNCheck(ProcessLine);
         if ValidMNCheck<>'' then outGOingMsjsAdd(GetPTCEcn+ValidMNCheck)
         //PTC_MNCheck(ProcessLine)
         end
```

- **Why it is vulnerable:** `ParseProtocolLines` drains one slot's queue completely before moving on, from the GUI thread's heartbeat. `ADMINMSG` and `$MNCHECK` each perform EC verification there, and neither has the `addipcontrol` limit that `ORDER` and `$CUSTOM` have. Each `SlotLines` list is unbounded. Valid-format junk costs the sender nothing, while the receiver pays one curve verification per line.
- **Attacker and preconditions:** Any peer past the handshake.
- **Impact on a live network:** Late block building and timeouts on other peers. A late `BuildNewBlock` can change which orders meet the time rule.
- **Consensus change:** No.
- **Fix:** Process lines off the GUI thread, with per-peer rate limits and queue caps. Check cheap conditions first, for example the message hash and the seen list before the signature.

### M-08. Costly unauthenticated requests have no rate limit

- **Severity:** MEDIUM. Small requests trigger large disk, CPU and network work.
- **Status:** Confirmed by reading.
- **Location:** `masterpaskalform.pas:2492-2563`, `masterpaskalform.pas:2751-2768`, `masterpaskalform.pas:2690-2701`, `mpprotocol.pas:639-674`.

`masterpaskalform.pas:2528-2536`
```pascal
   else if parameter(LLine,4) = '$LASTBLOCK' then
      begin // START SENDING BLOCKS
      AddFileProcess('Send','Blocks',IPUser,GetTickCount64);
      BlockZipName := CreateZipBlockfile(StrToIntDef(parameter(LLine,5),0));
      if BlockZipName <> '' then
         begin
         MemStream := TMemoryStream.Create;
            TRY
            MemStream.LoadFromFile(BlockZipName);
```

`masterpaskalform.pas:2751-2760`
```pascal
    else if parameter(LLine,0) = 'GETZIPSUMARY' then  //
      begin
      MemStream := TMemoryStream.Create;
      if GetZIPSummaryAsMemStream(MemStream) > 0 then GetFileOk := true
      else GetFileOk := false;
      if GetFileOk then
         begin
            TRY
            Acontext.Connection.IOHandler.WriteLn('ZIPSUMARY '+Copy(MySumarioHash,0,5));
            Acontext.connection.IOHandler.Write(MemStream,0,true);
```

- **Why it is vulnerable:** Every `$LASTBLOCK` line builds a new archive of up to 101 block files under a global lock, then loads it into memory. The rate limits in `PTC_SendBlocks` and `PTC_SendSumary` are not on the server path, which handles these lines directly in `IdTCPServer1Execute`. `GETZIPSUMARY`, `$GETSUMARY` and `NSLGVT` send whole files. The only limit is `AddIPControl`, at 100 connections per IP per minute, and it does not count lines on an open slot. `Blocks_x_y.zip` names can collide between concurrent requests, and one request's delete can break another's transfer.
- **Attacker and preconditions:** Any client. Handshake needed for `$`-prefixed commands only.
- **Impact on a live network:** Bandwidth amplification and slower seeds, which feeds H-04.
- **Consensus change:** No.
- **Fix:** Add per-peer and global limits, cache recent archives, and use unique temporary names.

### M-09. Binary files from peers are parsed with unchecked counts and lengths

- **Severity:** MEDIUM. Forged files can cause large allocations, slow loops, out-of-bounds reads and exceptions in critical paths. No write overflow was found.
- **Status:** Confirmed by reading.
- **Location:** `nosopsos.pas:159-172`, `mpblock.pas:669-683`, `mpdisk.pas:720-722`, `nosoblock.pas:373-377`, `nosoblock.pas:18-40`.

`nosopsos.pas:165-172`
```pascal
      SetPSOHeaders(NewHeader);
      TRY
        for counter := 0 to NewHeader.MNsLock-1 do
        begin
        MNData := Default(TMNsLock);
        MyStream.Read(MNData,sizeof(MNData));
        InsertLockedMN(MNData);
        end;
```

`mpblock.pas:669-683`
```pascal
   MemStr.Read(posreward, SizeOf(int64));
   MemStr.Read(totalposes, SizeOf(integer));
   SetLength(ArrayPos,totalposes);
   For Counter := 0 to totalposes-1 do
      MemStr.Read(ArrayPos[Counter].address,Sizeof(ArrayPos[Counter]));
   // MNS INFO
   MemStr.Read(MNReward, SizeOf(MNReward));
   MemStr.Read(totalMNs, SizeOf(totalMNs));
   SetLength(resultado,totalMNs);
   For Counter := 0 to totalMNs-1 do
      begin
      MemStr.Read(resultado[Counter].address,Sizeof(resultado[Counter]));
      end;
   SetLength(resultado,totalMNs+1);
   resultado[length(resultado)-1].address := IntToStr(MNReward);
```

`mpdisk.pas:720-722`
```pascal
   ArrayMNs := GetBlockMNs(BlockNumber);
   MNsReward := StrToIntDef(ArrayMNs[length(ArrayMNs)-1].address,0);
   SetLength(ArrayMNs,length(ArrayMNs)-1);
```

- **Why it is vulnerable:**
  - `NewHeader.MNsLock` is an unchecked 32-bit count, and each pass calls `Insert` even after end of stream, because `Read` does not raise. A forged header gives a loop that grows a very large array, and each step may copy it, so it is an effective hang.
  - `GetBlockMNs` ignores short reads, so `totalposes` and `totalMNs` can be uninitialized stack values when a file is truncated.
  - `GetBlockMNs` returns an empty array when the file is missing or broken, and callers then index `[length-1]`, that is `[-1]`. With range checks off, this is an invalid read.
  - ShortString fields loaded by raw `Read` keep whatever length byte the file has, for example 255 in a `String[32]`. Later string use reads past the field, which is an over-read of neighbouring memory, though a write is not possible since assignment truncates.
- **Attacker and preconditions:** Delivery of a forged file (C-02, C-03, H-06). The PSO case is reachable by a single inbound message, as H-06 explains.
- **Impact on a live network:** Node hang or crash after forged data, plus stuck state such as `RebuildingSumary` remaining true with no `finally`.
- **Consensus change:** No.
- **Fix:** Check the file size against the claimed counts before allocating. Check every `Read` result. Validate ShortString length bytes when loading. Return an error rather than an empty array, and handle it at each call.

### M-10. Block content depends on each node's local mempool

- **Severity:** MEDIUM. Honest nodes can build different blocks for the same height, and a peer can provoke this at will.
- **Status:** Confirmed by reading.
- **Location:** `mpblock.pas:170-231`, `masterpaskalform.pas:2036-2040`, `nosomasternodes.pas:507-528`.

`mpblock.pas:186-191`
```pascal
      if ( (ArrayPoolTXs[contador].TimeStamp+60 > TimeStamp) or (BlockTrfrs>=2000) ) then
         begin
         if ArrayPoolTXs[contador].TimeStamp < TimeStamp+600 then
            insert(ArrayPoolTXs[contador],IgnoredTrxs,length(IgnoredTrxs));
         continue;
         end;
```

- **Why it is vulnerable:** Every node builds the block from its own pending pool, its own masternode list and its own checks. There is no block proposal. The block is whichever hash wins the seed vote, and other nodes then undo theirs and download. An order that some seeds see before the cut-off `TimeStamp + 60` and others see after makes their blocks differ. The same is true for `$MNCHECK` and `$MNREPO` messages delivered selectively.
- **Double spend:** Within one node's block, a double spend is blocked, because `SummaryValidPay` debits in sequence through `BlockRecords`. Across nodes, two conflicting orders delivered to different seeds give different valid-looking blocks, and the vote then picks one. A confirmed transfer on the losing side is undone, since one vote is all the finality there is. There is no confirmation depth at which reversal becomes impossible short of H-04's fix. C-04 replay remains the simpler practical double debit.
- **Attacker and preconditions:** A peer that sends a message to a subset of seeds around the cut-off time.
- **Impact on a live network:** Repeated rollback and download on many nodes, reversal of recently confirmed payments, more use of the C-03 path, and a split when no hash dominates.
- **Consensus change:** Yes.
- **Fix:** Have a defined proposer per block and verify its content, or commit to a pre-agreed order set before the boundary.

### M-11. Block building and block replay do not produce the same summary

- **Severity:** MEDIUM. A node cannot reliably recompute the summary from blocks, so it falls back to downloading it, which is the C-03 trust path.
- **Status:** Confirmed by reading for the differing code. The effect on the file hash is inferred, not executed.
- **Location:** `mpblock.pas:352-355`, `mpdisk.pas:678-729`, `mpblock.pas:217-229`, `nosounit.pas:132`, `masterpaskalform.pas:582`.

`mpblock.pas:352-355`
```pascal
   PoWTotalReward := (GetBlockReward(Numero)+MinerFee)-PosTotalReward-MNsTotalReward-DevsTotalReward;
   CreditTo(Minero,PoWTotalReward,numero);
   // Update summary lastblock
   CreditTo('N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd',0,numero);
```

`mpdisk.pas:678`
```pascal
CreditTo(BlockHeader.AccountMiner,BlockHeader.Reward+BlockHeader.MinerFee,BlockNumber);
```

`mpdisk.pas:729`
```pascal
CreditTo(AdminHash,0,BlockNumber);
```

- **Why it is vulnerable:** `BuildNewBlock` touches `N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd`, record 0 of the summary, whose `LastOP` is read back as `SummaryLastop`. `AddBlockToSumary` touches `AdminHash`, which is `N3DthVsfEUtqrgWFHTEB6F88xLkT3Df`, a different record. Replay therefore leaves record 0's `LastOP` stale and changes another record's. The file bytes, and thus the MD5, differ. `SNDGVT` also differs: building charges `AmmountFee`, replay charges `GetCustFee`. The replay `else` branch at `mpdisk.pas:697` debits the miner on a failed transfer, a case that building never creates. PoS bounds differ too: `numero < PosBlockEnd` against `blocknumber <= PoSBlockEnd`.
- **Attacker and preconditions:** None. This is a correctness issue with a security result.
- **Impact on a live network:** `CompleteSumary` output fails the vote, so the node requests the summary from a peer (`mpred.pas:760-769`). Nodes in practice trust downloads rather than their own computation.
- **Consensus change:** Fixing replay is local if it matches the build path byte for byte.
- **Fix:** Use one state-transition function for building and replay, and test it against real history.

### M-12. State changes are not atomic, and write failures do not stop the node

- **Severity:** MEDIUM. A crash or a full disk can leave ledger files inconsistent, and only one block can be undone.
- **Status:** Confirmed by reading.
- **Location:** `mpblock.pas:387-389`, `mpblock.pas:156`, `mpblock.pas:692-704`, `nosounit.pas:529-557`, `nosounit.pas:197-208`.

`mpblock.pas:387-389`
```pascal
   if not GuardarBloque(FileName,BlockHeader,ListaOrdenes,PosReward,PosCount,PoSAddressess,
                        MNsReward, MNsCount,MNsAddressess) then
      ToLog('exceps',FormatDateTime('dd mm YYYY HH:MM:SS.zzz', Now)+' -> '+'*****CRITICAL*****'+slinebreak+'Error building block: '+numero.ToString);
```

`mpblock.pas:692-704`
```pascal
Procedure UndoneLastBlock();
Const
  Highest : integer = 0;
var
  blocknumber : integer;
Begin
blocknumber:= MyLastBlock;
if BlockNumber < Highest then
   begin
   ToLog('Console','Can not undo block '+mylastblock.ToString);
   exit;
   end
else Highest := BlockNumber;
```

- **Why it is vulnerable:** Summary, GVT and block files are written separately, in place, with no journal. `UpdateSummaryChanges` swallows every error in an empty `EXCEPT`. A block save failure is logged and execution continues, which advances `MyLastBlock`. `CreateSumaryBackup` results are ignored, and there is one `.bak`, so a two-block undo restores the wrong state. The typed constant `Highest` blocks a second undo until the height recovers. Downloads overwrite files directly, so a dropped stream leaves a partial file.
- **Attacker and preconditions:** Disk exhaustion (C-02 can cause it) or a crash at the wrong time.
- **Impact on a live network:** Silent state divergence on the affected node.
- **Consensus change:** No.
- **Fix:** Write to temporary files and rename after an fsync. Stop on any failed write. Keep several rollback points, or derive state from blocks.

### M-13. SHA-1 signatures, MD5 identities and signature malleability

- **Severity:** MEDIUM. These are real weaknesses, but in this code each one has a cheaper alternative in the Critical list, and practical attacks on them are limited.
- **Status:** Confirmed by reading.
- **Location:** `mpsignerutils.pas:54`, `nosocrypto.pas:189-202`, `mpblock.pas:398`, `Packages/CryptoLib4Pascal.zip -> CryptoLib4Pascal-master/CryptoLib/src/Crypto/Signers/ClpECDsaSigner.pas:217`.

`mpsignerutils.pas:54`
```pascal
    SigningAlgorithm = 'SHA-1withECDSA';
```

`mpblock.pas:398`
```pascal
   MyLastBlockHash := HashMD5File(BlockDirectory+IntToStr(MyLastBlock)+'.blk');
```

- **Why it is vulnerable:**
  - `SHA-1withECDSA` is the only scheme. A chosen-prefix SHA-1 collision is feasible for a funded attacker, though it needs the victim to sign attacker-prepared text, and the digit and address format leaves little room.
  - Block identity, summary identity and every voted hash are MD5. MD5 collisions are cheap. They are not needed today because the 20-bit check is weaker still, but they become relevant if only the prefix is fixed.
  - The signer does not normalize to low-S, and the verifier accepts both forms, so a third party can produce a second valid signature for any message. Because `TrfrID` is not bound (C-04), this adds little today, but it would matter once IDs include the signature.
- **Mitigation that holds:** ECDSA nonces come from `TRandomDsaKCalculator` over `TSecureRandom`, which is seeded from the operating system source, not the Pascal `Random`.
- **Attacker and preconditions:** Well-funded attacker for hash collisions. Anyone for malleability.
- **Impact on a live network:** Long-term loss of integrity guarantees.
- **Consensus change:** Yes.
- **Fix:** Move to SHA-256 or better with enforced low-S, and to SHA-256 for all identities, at a defined activation height.

### M-14. GVT state is unauthenticated and its rules disagree across paths

- **Severity:** MEDIUM. GVT ownership can be forged on a node, and GVT transfers do not follow the documented owner model.
- **Status:** Confirmed by reading.
- **Location:** `nosonetwork.pas:1243-1257`, `nosogvts.pas:80-94`, `nosogvts.pas:144-175`, `mpprotocol.pas:956-985`, `mpprotocol.pas:282`, `mpblock.pas:217-229`, `mpdisk.pas:687-692`.

`mpprotocol.pas:975`
```pascal
  if OrderInfo.sender <> AdminPubKey then ErrorCode := 8;
```

`nosogvts.pas:160-175`
```pascal
Function ChangeGVTOwner(Lnumber:integer;OldOwner,NewOWner:String): integer;
var
  LData : TGVT;
Begin
  result := 0;
  if LNumber > 99 then result := 1;
  LData := GetGVTIndex(Lnumber);
  if LData.owner <> OldOwner then result := 2;
  if not IsValidHashAddress(NewOWner) then result := 3;
  if result = 0 then
    begin
    EnterCriticalSection(CSGVTsArray);
    ArrGVTs[Lnumber].owner := NewOWner;
    LeaveCriticalSection(CSGVTsArray);
    end;
End;
```

- **Why it is vulnerable:**
  - `GVTSFILE` replaces the GVT file on any outbound connection, with no request and no hash check.
  - `PTC_SendGVT` requires `sender = AdminPubKey`, so a real owner's `SendGVT` cannot pass, even though `SendGVT` in `mpparser.pas` lets an owner sign. The admin can move any GVT whose owner field equals the admin address only, since `ChangeGVTOwner` compares owners, so owners' tokens are effectively frozen.
  - `$SNDGVT` is commented out in the dispatcher (`mpprotocol.pas:282`), so only `NSLSENDGVT` is processed, and peers ignore the `$SNDGVT` lines that `PTC_SendGVT` relays.
  - `ChangeGVTOwner` guards `LNumber > 99` but not negatives, and `GetGVTIndex` checks only the upper bound. A negative `Reference` then reads out of bounds. `GVTAlreadyTransfered` blocks negatives on the normal path, so this needs an order type bypass and the admin key.
  - `SummaryValidPay`'s result is ignored at `mpblock.pas:225`, after the fee has been counted in `minerfee`.
  - `TGVT.owner` is `string[32]`, so a longer address truncates.
- **Attacker and preconditions:** A peer the victim connects to, for forged files. The other items need the admin key.
- **Impact on a live network:** Wrong GVT listings on affected nodes until the 5-character hash triggers a redownload, and a non-functional transfer feature.
- **Consensus change:** Yes for the rule changes.
- **Fix:** Derive GVT state from blocks. Let the owner's key authorize. Check both bounds. Count the fee only after the debit succeeds.

### M-15. Unchecked indexing and casts in input parsing

- **Severity:** MEDIUM. Malformed input can read invalid memory. Reachability is limited to RPC clients and the console, so the risk is below a network-wide crash.
- **Status:** Confirmed by reading. Exploitability beyond a crash is not established.
- **Location:** `nosocrypto.pas:404-407`, `mprpc.pas:462-467`, `mpprotocol.pas:1034-1036`, `nosonosocfg.pas:144`, `nosonosocfg.pas:191`, `nosonosocfg.pas:224`.

`nosocrypto.pas:404-407`
```pascal
    DataArray   := SplitString(Certificate,':');
    Address     := GetAddressFromPublicKey(DataArray[1]);
    CertTime    := DataArray[2];
    Signature   := DataArray[3];
```

`mprpc.pas:460-467`
```pascal
   jData := GetJSON(jsonreceived);
      try
      jObject := TJSONObject(jData);
      method := jObject.Strings['method'];
      params := jObject.Arrays['params'];
      jsonid := jObject.Integers['id'];
      for counter := 0 to params.Count-1 do
         NosoPParams:= NosoPParams+' '+params[counter].AsString;
```

- **Why it is vulnerable:** After a public checksum, `CheckCertificate` indexes `DataArray[1..3]` from `SplitString` with no length check. In Release there is no range check, so a value past the array end is treated as a managed string and reference-counted. `TJSONObject(jData)` is a hard cast with no type test, so a JSON array or number reaches object methods. `RemoveCFGData` and `SetCFGData` index an array that may be shorter than the field number. `AddCFGData` reads `DataToAdd[Length(DataToAdd)]`, which is index 0 for empty text. An admin directive with an empty parameter reaches it.
- **Attacker and preconditions:** Access to RPC (see H-09), or a signed directive for the CFG items.
- **Impact on a live network:** The exception handlers catch most of these. The garbage reference-count write in `CheckCertificate` is the one memory-corruption concern.
- **Consensus change:** No.
- **Fix:** Check array lengths, use `is`/`as` for JSON types, and build with range checks.

### M-16. Build and release chain has unpinned third parties and binary blobs

- **Severity:** MEDIUM. The release asset is what auto-update executes, so this widens C-08.
- **Status:** Confirmed by reading of the workflow. Binary files were not audited.
- **Location:** `.github/workflows/main.yaml:13-14`, `.github/workflows/main.yaml:34`, `.github/workflows/main.yaml:135`, `Packages/*.zip`, `ssl/`.

`.github/workflows/main.yaml:13-14`
```yaml
permissions:
  contents: write
```

`.github/workflows/main.yaml:34`
```yaml
      uses: gcarreno/setup-lazarus@v3.2
```

`.github/workflows/main.yaml:135`
```yaml
      uses: softprops/action-gh-release@v1
```

- **Why it is vulnerable:** Third-party actions are pinned to movable tags while the job holds `contents: write`, and `softprops/action-gh-release@v1` also receives `GITHUB_TOKEN`. Dependencies are committed as zip files with no recorded provenance or hash. Prebuilt OpenSSL DLLs and RAR archives are in the tree.
- **Attacker and preconditions:** Compromise of an action's tag or of a dependency source.
- **Impact on a live network:** A poisoned official release.
- **Consensus change:** No.
- **Fix:** Pin actions to commit hashes, use least-privilege job tokens, record dependency hashes, build from source and make builds reproducible.


## Low findings

### L-01. Address validation accepts unspendable forms

- **Severity:** LOW. The checksum catches some typos only, and `M` addresses can receive funds with no way to spend them.
- **Status:** Confirmed by reading.
- **Location:** `nosocrypto.pas:327-342`, `nosocrypto.pas:679-689`.

`nosocrypto.pas:335-340`
```pascal
  if ((length(address)>20) and ((address[1] = 'N') or (address[1] = 'M')) ) then
    begin
    OrigHash := Copy(Address,2,length(address)-3);
    if IsValid58(OrigHash) then
      if FirstChar+OrigHash+(B10toB58(BMB58resumen(OrigHash))) = Address then
        result := true;
```

- **Why it matters:** The checksum is a sum of digit values, so swapping two characters does not change it. Any string of the right shape is valid, and an `M` prefix passes, but no live rule lets `M` funds move. Funds sent to a typo that keeps the sum, or to an `M` address, are stuck.
- **Attacker and preconditions:** None, user error.
- **Impact:** Lost funds for individuals.
- **Consensus change:** Yes, if enforced in rules. A client-side warning is enough at first.
- **Fix:** Use a real checksum for a new address version.

### L-02. `IsValidIP` accepts private and reserved ranges

- **Severity:** LOW. Verifiers will open connections to internal addresses, but only send `MNVER`.
- **Status:** Confirmed by reading.
- **Location:** `nosogeneral.pas:194-210`.

`nosogeneral.pas:204-209`
```pascal
  if ((valor1 <0) or (valor1>255)) then result := false;
  if ((valor2 <0) or (valor2>255)) then result := false;
  if ((valor3 <0) or (valor3>255)) then result := false;
  if ((valor4 <0) or (valor4>255)) then result := false;
  if ((valor1=192) and (valor2=168)) then result := false;
  if ((valor1=127) and (valor2=0)) then result := false;
```

- **Why it matters:** `10.0.0.0/8`, `172.16.0.0/12`, `127.x` other than `127.0.x`, `0.0.0.0` and multicast all pass, and five-part values pass as well. Seed nodes then make a small request to such addresses.
- **Attacker and preconditions:** Listing a masternode (H-01).
- **Impact:** Limited internal port probing from seed hosts.
- **Consensus change:** Yes for masternode list rules.
- **Fix:** Accept only public unicast IPv4 with exactly four parts.

### L-03. Lock and result-handling errors

- **Severity:** LOW. These are minor bugs that make failures harder to reason about.
- **Status:** Confirmed by reading.
- **Location:** `nosomasternodes.pas:778-788`, `nosonetwork.pas:281-329`, `mpprotocol.pas:956-964`.

`nosomasternodes.pas:781-787`
```pascal
  if LengthWaitingMNs>0 then
    begin
    EnterCriticalSection(CSWaitingMNs);
    Result := ArrWaitMNs[0];
    Delete(ArrWaitMNs,0,1);
    end;
  LeaveCriticalSection(CSWaitingMNs);
```

- **Why it matters:** `GetWaitingMNs` calls `LeaveCriticalSection` even when it did not enter. `AddArrayPoolTXs` leaves `Result` unset on early exits. `PTC_SendGVT` returns an unset value on a parse failure, and that value is sent to the client.
- **Attacker and preconditions:** Timing only.
- **Impact:** Unpredictable behaviour in edge cases.
- **Consensus change:** No.
- **Fix:** Set results at entry. Pair each lock with `try..finally`.

### L-04. Global rate-limit timers let one peer starve others

- **Severity:** LOW. These legacy handlers are mostly unused on the server path.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:474-479`, `mpprotocol.pas:511-516`, `mpprotocol.pas:690-691`, `mpprotocol.pas:1098-1103`.

`mpprotocol.pas:1102-1103`
```pascal
if UTCTime < LastRequest + 10 then exit;
LastRequest := UTCTime;
```

- **Why it matters:** `LastRequest` is one static value per handler, not per peer. One peer's `GETHEADUPDATE` every 10 seconds denies everyone else this service.
- **Attacker and preconditions:** Any peer past the handshake.
- **Impact:** Slower header updates for others, which leads to full header downloads.
- **Consensus change:** No.
- **Fix:** Keep limits per peer.

### L-05. Ownership certificates have no audience, and XOR adds nothing

- **Severity:** LOW. A captured certificate works for anyone, forever.
- **Status:** Confirmed by reading.
- **Location:** `nosocrypto.pas:362-383`, `nosocrypto.pas:386-416`.

`nosocrypto.pas:372-375`
```pascal
    Signature   := GetStringSigned('OWN'+Address+currtime,PrivKey);
    Certificate := 'OWN:'+Pubkey+':'+Currtime+':'+signature;
    //ToLog('console','To encode: '+certificate);
    Certificate := UPPERCASE(XorEncode(HashSha256String('noso'),certificate));
```

- **Why it matters:** The signed text is `OWN + address + time`, with no verifier name or challenge, so a service that accepts one as proof of ownership can be replayed against by anyone who has seen it. The XOR key is a fixed public hash, so this is encoding rather than encryption.
- **Attacker and preconditions:** Anyone who sees a certificate.
- **Impact:** Impersonation at services that trust these certificates.
- **Consensus change:** No.
- **Fix:** Sign a verifier-supplied nonce and an audience.

### L-06. `GetSupply` is wrong after block 210000 and returns 0 after 420000

- **Severity:** LOW. It affects reporting and has no spending effect at current rules.
- **Status:** Confirmed by reading.
- **Location:** `nosogeneral.pas:213-223`, `mprpc.pas:634-636`, `nosogeneral.pas:285-290`.

`nosogeneral.pas:213-223`
```pascal
Function GetSupply(block:integer):int64;
Begin
  Result := 0;
  if block < 210000 then
    result := (block*5000000000)+1030390730000
  else if ((block >= 210000) and (block < 420000)) then
    begin
    Inc(result,(209999*5000000000)+1030390730000);
    Inc(result,(block-209999)*5000000000);
    end;
End;
```

- **Why it matters:** The second branch keeps counting at 50 NOSO after the first halving, and the function has no branch beyond 420000. `GetStackRequired` is unaffected above block 110000 because it uses a constant. RPC `getmainnetinfo` reports the wrong supply, and `ShowSumary`'s supply check becomes meaningless.
- **Attacker and preconditions:** None.
- **Impact:** Wrong public supply figures, which also hides inflation from C-05 and C-06.
- **Consensus change:** No.
- **Fix:** Compute from the real halving schedule, and add a real supply audit.

### L-07. Peer-controlled text reaches logs without limit

- **Severity:** LOW. Disk and GUI memory fill slowly, and log lines can be forged.
- **Status:** Confirmed by reading.
- **Location:** `mpprotocol.pas:288`, `mpprotocol.pas:861-862`, `nosodebug.pas:233-247`.

`mpprotocol.pas:288`
```pascal
         ToLog('Console','Unknown command () in slot: ('+ProcessLine+') '+intToStr(contador)); //Unknown command () in slot: (
```

- **Why it matters:** Unknown commands and every order line are logged with no size limit or newline escaping. There is no log rotation, except for the merge at startup.
- **Attacker and preconditions:** Any peer past the handshake.
- **Impact:** Disk growth and misleading logs.
- **Consensus change:** No.
- **Fix:** Rate-limit, truncate and escape log input, and rotate files.

### L-08. Fixed-size fields silently truncate addresses

- **Severity:** LOW. Real addresses are short enough today, but state code assumes no truncation.
- **Status:** Confirmed by reading.
- **Location:** `masterpaskalform.pas:186-188`, `nosopsos.pas:28-31`, `nosogvts.pas:11-16`, `nosomasternodes.pas:22-32`.

`masterpaskalform.pas:186-188`
```pascal
  TArrayPos = Packed Record
       address : string[32];
       end;
```

- **Why it matters:** `TMNode.Fund` holds 40 characters while `TArrayPos.address`, `TMNsLock.address` and `TGVT.owner` hold 32. A valid-format address longer than 32 characters would be paid or locked under a shortened name. Real key-derived addresses are about 31 characters, so this needs a crafted non-key address, which only harms the crafter.
- **Attacker and preconditions:** Registering such an address.
- **Impact:** Burned rewards. Mainly a compatibility trap.
- **Consensus change:** Yes, if the field is changed.
- **Fix:** Reject over-length addresses at the entry points.


## Checked, no finding

These were examined so that their absence from the list above is not ambiguous.

- **ShortString overflow from the wire.** `GetOrderFromString`, `ProcessPing`, `GetMNodeFromString` and similar code assign `AnsiString` values to `String[N]`, which truncates. No write overflow was found. Over-reads through raw file loads are covered in M-09.
- **`Parameter()` bounds.** It walks characters with bounds, and it returns empty for bad parenthesis nesting.
- **Negative amounts in `TRFR`.** `ValidateTrfr` rejects negative `AmmountTrf` and `AmmountFee` (`mpprotocol.pas:796-799`). The overflow in C-05 uses non-negative values.
- **Double spend inside one block.** `SummaryValidPay` debits in order through `BlockRecords`, so one block cannot overspend an address. Across nodes and forks, see M-10.
- **Order line count.** `NumTransfers` above 30 is rejected, and zero or negative counts fail the fee test (`mpprotocol.pas:866`, `mpprotocol.pas:906`).
- **Sender key to address binding.** `GetAddressFromPublicKey(sender)` must match `Address` in `PTC_Order` and `PTC_Custom`, and `ValidateTrfr` re-checks `origen`. A signature from a different key cannot spend someone else's address.
- **Signature parsing fails closed.** `VerifySignedString` catches exceptions and returns false, and CryptoLib treats a DER decode error as a failed verification.
- **ECDSA nonce and key generation.** They use `TSecureRandom`. Pascal `Random` is used only for non-secret choices (peer selection, delays).
- **Reward arithmetic for honest input.** Remainders from integer division return to the miner share, so splits do not create or lose coins, leaving aside the fee paths in C-05 and C-06.
- **`GetBlockReward`.** The halving schedule stops at step 10 and then returns 0.
- **`IsSeedNode` substring match.** Fixed, it matches `:ip;` and not a bare substring. `IsAddressLocked` keeps a substring match but addresses are fixed-format, so this was not a practical problem.
- **Format strings.** `Format` calls use constant format strings.
- **`PSO` orders.** PSOs are not processed by block building. `AddNewPSO` is reached only from the local `NEWPSO` test command. The live PSO surface is the file (H-06) and the masternode lock table.
- **Deprecated code.** `Noso.lpr` and `Noso.lpi` do not reference `Deprecated/`. The root file `mpmn.pas` and the commented-out blocks in live units are also not compiled, so bugs there are not reported. Note `MN_AutoIP` checks exist only in that dead `mpmn.pas`.
- **Vendored packages.** Reviewed only where a finding depends on them: Indy `ReadStream` and timeouts, CryptoLib signer, DER handling and RNG selection. The rest of `Packages/` was not audited.
- **`formexplore.pas`, `mpgui.pas`, `translation.pas`, `mplang.pas`.** Local GUI code only. Skimmed for network input and none was found, with no line-by-line review.
