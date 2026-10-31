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
| 9 | Dev payment order id is `"1" + TrfrID` (no hash); the miner is always the project funds address | `mpblock.pas:53`, `masterpaskalform.pas:2039` | `createDevPaymentOrder`, `network.BuildMiner` |
| 12 | PoS/MN percentage steps use 88400 while the PoS end constant is 88500 | `nosogeneral.pas:299,315,322` | `consensus` |
| 13 | `GetSupply` is 0 from block 420000 | `nosogeneral.pas:213-223` | `consensus.GetSupply` |
| 14 | `ProtocolLine` advertises `0.4.4zzz`, `GetPTCEcn` `0.4.4Ab9` | `nosonetwork.pas:376,412` | `Engine.ProtocolLine` |
| 15 | `$LASTBLOCK` is answered with blocks n+1.. on the dispatcher path and n.. on the server path | `mpprotocol.pas:693`, `masterpaskalform.pas:2531` | `sendBlocks`, `handleLine` |
| 16 | `ValidProtocolCommands` is a substring test (an empty command passes) | `masterpaskalform.pas:2602` | `network.ValidProtocolCommands` |
| 20 | The `NSLORDER` text is also broadcast to all peers | `mpparser.pas:813-818` | `Engine.SendFunds` |
| 21 | Orders already mined are found only through the optional blocks database | `mpred.pas:893` | `Engine.OrderDetails` |
| 22 | `Trim(result)` calls whose value is discarded leave trailing blanks (`NSLPEND`, locked MNs) | `mpcoin.pas:454`, `nosopsos.pas:368` | `PendingRawInfo`, `PSOs.LockedRaw` |
| 23 | JSON: `/` escaped, non-ASCII as `\uXXXX`; wrong-shaped requests give an empty body | `fpjson`, `mprpc.pas` | `rpc/json.go`, `rpc.Parse` |
| 24 | `StrToInt`-family functions accept `$FF`, `0xFF`, `&17`, `%101` and fail on trailing blanks | FPC `Val` | `codec.StrToInt64` |
| 26 | ShortStrings truncate silently; bytes after a shortened string keep their old values | FPC | `codec.PutShort` |
| 27 | `GetMultiSource` can duplicate entries while sorting | `nosocrypto.pas:475` | `crypto.GetMultiSource` |

## 2. Security fixes (SECURITY_REVIEW.md)

Every finding of `SECURITY_REVIEW.md` is fixed, overriding "preserve exactly"
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
| C-03 | Block validator (number, parent hash, slots, reward, fees, order shape, project payment, masternode share); summary/headers/GVT files must match the peer's advertised full hash and the consensus prefix; replay of an unfunded transfer removes the block and restores the summary | yes (blocks of the old chain fail the TrfrID rule) | `TestC02_C03_StageBlocks`, `TestC03_ReplayRollsBack`, `TestH05_RequestedFileHashChecked` |
| C-04 | `TrfrID` derived from all signed fields and recomputed on receipt and in blocks; replay window of three blocks | yes | `TestC04_TrfrIDBoundAndReplay` |
| C-05 | Amounts and fee range checked, sums with overflow checks, negative credits/debits refused in the summary | yes (rejects what wrapped in history) | `TestC05_Overflow`, `TestSummaryRefusesGarbageAddresses` |
| C-06 | `CUSTOM` fee must equal the exact custom fee, amount 0, valid unused alias; the debit equals the fee | yes | `TestC06_CustomFee` |
| C-07 | Validators registered per IP with their sign address (`ValidatorKeys`); check signed over block, validator and nodes under its own domain; each IP counted once per check | yes | `TestMNChecksSecurity` |
| C-08 | `update`, `getbeta`, `checkupdates`, `sendreport`, `testnet` and the update/restart directives removed; nothing is downloaded or run | yes (directives ignored) | `TestC08_NoUpdateCommands`, `TestH02_DirectiveReplay` |
| H-01 | Reports carry the fund owner's key and signature, bound to the current block; funds and zero-validation checks apply to every report | yes | `TestMNReportSecurity` |
| H-02 | Directive signature covers sequence, expiry height and a domain tag; sequence persisted (`directive.seq`) | yes | `TestH02_DirectiveReplay`, `TestH02_DirectiveOverTheWire` |
| H-03 | No built-in admin key; `AdminKey`/`ConfigKey` configurable; directives cannot move funds | yes | `TestC01_NoSoPayAndSignedConfig`, `TestH02_DirectiveReplay` |
| H-04 | More than half of all configured (deduplicated) seeds must agree; optional signed status per seed (`SeedKeys`); at most 20 blocks deleted on the word of peers, `RemoveBlocks` terminates. The vote values are still 5-character prefixes of 128-bit hashes (see notes) | partly (signed status suffix is ignored by old nodes) | `TestH04_QuorumAndDedupe`, `TestH04_SignedStatus`, `TestH04_ReorgDepth` |
| H-05 | `RESUMENFILE`/`HEADUPDATE` only as answers, matching hash and local blocks; a headers mismatch no longer wipes the pool | yes | `TestC02_H05_H06_UnsolicitedFilesRefused`, `TestH05_RequestedFileHashChecked` |
| H-06 | `MNFILE`/`PSOSFILE` only as answers with hash/size checks | yes | `TestC02_H05_H06_UnsolicitedFilesRefused`, `TestM09_PSOCountsChecked` |
| H-07 | Canonical signed encoding: tag, chain id, domain, length-prefixed fields including type and reference | yes | `TestCanonicalSignVerify`, `TestC04_TrfrIDBoundAndReplay` |
| H-08 | Raw bytes are hashed; the lenient Base64 decode of messages is gone | yes | `TestCanonicalSignVerify` |
| H-09 | Bearer tokens (read/spend), loopback bind, Origin and content-type checks, no private key in answers | yes (clients must send a token) | `TestH09_RPCAccessControl`, `TestH09_LoopbackBindAndHostFilter` |
| H-10 | Wallet in `wallet.enc` (Argon2id + AES-256-GCM, mode 0600), migration of `wallet.pkw` which is zeroed and removed; key commands never echoed or logged | no (local file) | `TestH10_WalletEncryptionAndMigration`, `TestH10_SensitiveCommands` |
| H-11 | Per-kind maximum sizes, no presizing, whole-transfer deadline | no | `TestStreamLimits` |
| M-01 | Receiver-side alias rules; only `TRFR` in orders | yes | `TestC06_CustomFee`, `TestM01_OrderType` |
| M-02 | Certificates verified (Go default); seed list used only over https with a detached signature under `ReleaseKey` | no | `TestM02_SignedSeedList` |
| M-03 | Median of up to five NTP servers, at least two answers, correction limited to 120 s | no | `TestM03_MedianOffset` |
| M-04 | Peer statements about our IP ignored; `GETMIIP` needs two agreeing nodes and `MNAutoIp` | no | `TestM04_PeerCannotSetMyIP` |
| M-05 | `MNVER <nonce>`: answer signed by the Sign key over nonce, state and funds | yes | `TestM05_MNVERChallenge` |
| M-06 | One state lock for the shared flags, mutexes elsewhere, panics contained per connection; `go test -race` | no | `TestM15_PanicContained` and the race run of every package |
| M-07 | 200 lines per 10 s per connection | no | `TestRateLimits` |
| M-08 | 10 costly one-shot requests per minute per peer | no | `TestRateLimits` |
| M-09 | File counts checked against the size before parsing | no | `TestM09_PSOCountsChecked`, `FuzzDecodeBlock`, `FuzzPSOParse` |
| M-10 | Only a node with `BuildBlocks True` proposes blocks (default off); others follow and validate | yes (behavioural) | `TestM10_OnlyProposersBuild` |
| M-11 | Replay and build touch the same account; unfunded transfers invalidate a block | yes | `TestBuildTransferBlockAndReplay` |
| M-12 | fsync + rename + directory sync; failed writes stop the build and do not advance the chain | no | `TestM12_AtomicWrite`, `TestM12_WriteFailureStopsBuild` |
| M-13 | SHA-256 signatures with low-S, identities (`IDHash`) are 128 bits of SHA-256 instead of MD5 | yes | `TestLowSEnforced`, `TestIDHash` |
| M-14 | The GVT owner's key authorises a transfer; fee counted after the debit; both index bounds checked | yes | `TestM14_GVTOwner` |
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
* **M-10**: this removes the divergence by letting only configured proposers
  build; it does not add a multi-party commitment protocol.
* **H-10**: zeroing the plaintext wallet is best effort on journaling or flash
  storage.

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

* **No interoperability test.** Free Pascal is not installed and the live
  network was out of scope. Nothing here has talked to a real Pascal node.
* Key and signature Base64 decoding follows the documented FPC MIME mode;
  messages are no longer decoded.
* `Copy(s, 0, n)` is taken to return the first `n` characters (FPC 2.x and
  later).
* Record padding in `psos.dat` (3 bytes after `String[32]`) assumes default
  FPC record alignment; the padding bytes are not read.
* Text encoding: strings are passed as raw bytes. This matches FPC on Linux
  with UTF-8; on Windows with other code pages the original may re-encode
  non-ASCII text.
* `PTC_SendGVT` returns an undefined value for unparsable input in Pascal;
  0 is returned here.
* `IsValidIP` rejects `127.0.x.x` and `192.168.x.x`, so masternode logic
  cannot be exercised on loopback or LAN addresses.
* Timing: thread scheduling differs; the goroutine heartbeat runs every
  200 ms like the original timer but ordering within a tick may differ.
* Downloaded files are only hash-compared, as in the original.

## 5. Things found in the real data

* 11 of the 4956 accounts of the real summary at block 59238 are garbage
  names (`androidx.lifecycle.MutableLiveData@...`, 40 characters), a direct
  consequence of item 5.
* The real summary contains neither `AdminHash` nor the project funds account
  at that height, consistent with the build path touching only the genesis
  account (fixed to be the only behaviour, M-11).
