# Peer-to-peer protocol

Source of truth: `nosonetwork.pas`, `mpprotocol.pas`, `mpred.pas`,
`masterpaskalform.pas` (server events) of the original. Version 0.4.4,
protocol number 2.

## Framing

* TCP, default port 8080.
* A **line** is text followed by `CR LF` when written. When reading, the
  terminator is `LF` and one preceding `CR` is removed (Indy `WriteLn` /
  `ReadLn`). Text is UTF-8 bytes passed through unchanged.
* A **file** transfer is a line naming the file (`RESUMENFILE`,
  `SUMARYFILE`, `GVTSFILE`, `PSOSFILE`, `BLOCKZIP`) followed by a 4 byte
  big-endian signed length and that many bytes (Indy `Write(stream,0,true)`).
* Limits added by this port: lines up to 4 MiB, files up to 256 MiB.

## Two kinds of connection

When a socket opens, the server waits up to 1 second for **one line** and
decides what it is (`Engine.handleIncoming`):

### One-shot queries

The server answers one line and closes. Checked before anything else:

| First word | Answer |
|---|---|
| `NODESTATUS` | `NODESTATUS ` + 20 fields (see below) |
| `NSLORDER` | result of `PTC_Order` (order id, `ERROR n` or empty) |
| `NSLCUSTOM` | error code of `PTC_Custom` |
| `NSLSENDGVT` | error code of `PTC_SendGVT` |
| `GETMIIP` | the caller's IP |
| `MNVER` | `True <synctus> <fundsAddress> <callerIP> <signAddress>` or `False` |
| `NSLBALANCE addr` | available balance (summary minus pending) |
| `NSLPEND` / `NSLPENDFULL` | pending orders, comma fields, blank separated, trailing blank |
| `NSLBLKORD n\|LAST` | `NSLBLKORD n sender:receiver:amount:reference:orderid ...` |
| `NSLTIME` | UTC time |
| `NSLMNS` | masternodes file line |
| `NSLCFG` | nosocfg text |
| `NSLGVT` | `GVTFILE xxxxx` + file |
| `GETZIPSUMARY` | `ZIPSUMARY xxxxx` + zip |

Before these, a connection is refused with a single line: `BANNED` (known
bot), nothing (more than 99 connections from the IP in the last minute),
`Closing NODE` (the server is being closed). A node that is not up to date still
answers: what it serves is verified by the receiver.

### Peer connection

A line starting with `PSK ` registers a peer: `PSK <yourIP> <version> <utc> [<listenPort>]`. The
last field is an addition of this port: the port the dialler listens on (0 when
it does not). A peer is a host and a port; only loopback peers, which share an
address, are told apart by port, every other host counts once.
After the checks below the connection becomes a `CLI` slot (they dialled us);
connections we dial are `SER` slots. In order:

1. not starting with `PSK ` -> `WRONG_PROTOCOL` and the IP is remembered as a bot
2. the caller is our own public IP -> closed
3. time difference above 5 s (only when our last block is at least 70000) -> `WRONG_TIME`
4. the peer (host, or host and port on loopback) already has a slot -> `PSK 2 0.4.4Ab9 <utc> DUPLICATED`, no ban
5. peer version (first 3 characters) below `0.4` -> `... OLDVERSION->REQUIRED_0.4.4`
6. no free slot (99 maximum) -> closed

The dialling side sends `PSK <serverAddress> 0.4.4Ab9 <utc> <listenPort>` and then a PING. Loopback addresses are never banned and are exempt from the per-address flood counter.

## Protocol lines

`PSK 2 <version> <utc> <command> <args...>`; fields are blank separated and
read with the `Parameter` tokenizer (parentheses group text). COMPAT: lines
built by `ProtocolLine` advertise the version as `0.4.4zzz`, lines built by
`GetPTCEcn` advertise `0.4.4Ab9`.

| Command | Sent when | Meaning |
|---|---|---|
| `$PING` / `$PONG` | every 5 s, after a block, on connect | node state, see below |
| `$GETPENDING` | state 3 and peers have more pending | answer: `ORDER` lines and `$CUSTOM`/`$SNDGVT` lines |
| `$GETRESUMEN` | (served, never requested) | answer: `RESUMENFILE` |
| `GETHEADUPDATE n` | fewer than 144 blocks behind | answer: `HEADUPDATE $b:hash:sum b:hash:sum ...` |
| `$LASTBLOCK n` | a peer's PING shows a longer chain or another tip | answer: `BLOCKZIP` with blocks n+1.. (at most 101 and at most 32 MiB uncompressed, consecutive) |
| `$GETSUMARY`, `$GETGVTS`, `$GETPSOS` | (served, never requested: derived from the blocks) | `SUMARYFILE`, `GVTSFILE`, `PSOSFILE` |
| `GETMNSFILE` / `MNFILE $text` | masternodes hash differs | text accepted only if `MD5(text+CRLF)` starts with the consensus hash |
| `GETCFGDATA` / `SETCFGDATA $text` | cfg hash differs | accepted only if the first 5 hex chars of MD5 match consensus |
| `$GETMNS` | state 3 | answer: one `$MNREPO` line per known masternode |
| `$MNREPO ip port sign funds first last total validations hash` | new masternode report | validated and re-broadcast |
| `$GETCHECKS` / `$MNCHECK ip block signAddr pubkey nodes signature` | verifications | |
| `ORDER n $order $order ...` | new transfer | `n` transfers of 14 fields each |
| `$CUSTOM` / `$SNDGVT` | alias / GVT transfer | one order |
| `ADMINMSG` | developer directives | only config directives are executed |

An order is `TYPE ID LINES TYPE TIMESTAMP REFERENCE LINE SENDER ADDRESS
RECEIVER FEE AMOUNT SIGNATURE TRFRID` (the type appears twice: once as the
leading token and once as field 3).

### PING / PONG fields

After the four header fields, in order: 5 connections, 6 last block, 7 last
block hash (MD5 of the file), 8 summary hash (MD5 of `sumary.psk`), 9 pending
count, 10 headers hash (MD5 of `blchhead.nos`), 11 status 0-3, 12 listening
port (-1 when the server is off), 13 first 5 chars of the masternodes file
MD5, 14 masternode count, 15 `null`, 16 checks count, 17 GVT hash, 18 first 5
chars of MD5(nosocfg), 19 first 5 chars of the PSO file hash.

The receiver stores them and computes a **Merkle hash**
`MD5(lastBlock + h5(headers) + h5(mns) + h5(lastBlockHash) + h5(summary) +
h5(gvt) + h5(cfg))`, where `h5` is the first 5 characters. A peer is
"synced" when this equals the consensus hash.

### NODESTATUS fields

`NODESTATUS 1 peers 2 lastBlock 3 pending 4 delta 5 headers5 6 version
7 utc 8 mns5 9 mnsCount 10 lastBlockHash 11 null 12 lastBlockTimeEnd
13 lastMiner 14 checks 15 lastPoW 16 lastDiff 17 summary5 18 gvt5 19 cfg5
20 pso5`.

## Consensus (a hint, not a vote on the chain)

Every minute the node asks `NODESTATUS` to each seed in `nosocfg` field 1. The
consensus hash of a node is `MD5(lastBlock + headers5 + mns5 + lastBlockHash5 +
summary5 + gvt5 + cfg5)`. The most frequent hash wins, but only with more than
half of ALL configured seeds (a seed is a host and a port); then, parameter by
parameter, the most frequent value among the nodes that agree with the winner.
Item 0 is the hash itself and item N is NODESTATUS parameter N. The result is
used for the configuration, the masternode file and list and the verification
records. It decides nothing about blocks, the summary, headers, GVTs or PSOs.

## Connection state machine and block propagation

* 0: no connection (and nodes are configured). 1: fewer connections than
  needed. The number needed is `MinPeers` (1) but never more than the number of
  other configured nodes; with none configured the node is a standalone chain.
  2: connected, but a peer is ahead or on a tip not weighed yet. 3: up to date:
  no authenticated peer shows a longer chain or a tip that is not ours and has
  not already lost against ours.
* A node builds blocks in state 3 only (and only when it is its turn).
* Every PING carries the sender's last block number and tip hash and is sent
  every 5 s and whenever the tip changes (a built block, a stored archive).
  The receiver pulls: a peer ahead gets `$LASTBLOCK <our tip>`; a peer at our
  height or below with another hash at its height gets `$LASTBLOCK` from before
  our tip (the probe window doubles while answers do not link). A not yet
  heavier branch is staged by the node and the next window continues from its
  tip. Same question to the same peer at most every 10 s; one request in
  flight; a wrong claim costs one request.
* The answer goes to `node.StageBlocks`: seals, links, orders and the state are
  checked and the heavier branch wins (`consensus.md`). A fork, a lighter
  branch or an empty answer never closes the connection; only a peer that sends
  three invalid archives is dropped. A peer that sends an unsealed block is held
  back from block pull at once.
* `SyncWithMainnet` (every 4 s, block age 10-595) still requests the
  configuration, the masternode file, reported masternodes and verification
  records on the seed consensus; it never touches blocks or state files.

## Time

Block boundaries are multiples of 600 seconds of UTC time corrected by an
SNTP offset. The first 10 and last 15 seconds of a period ("block closed")
are ignored by most protocol handlers.

## Changes from the original protocol (security fixes)

The port deliberately departs from the Pascal wire protocol where
`SECURITY_REVIEW.md` found vulnerabilities (details and tests in
[compatibility.md](compatibility.md)). A Pascal node and this node do not
fully interoperate.

* **Files and configuration are answers only.** `BLOCKZIP`, `MNFILE` and `SETCFGDATA`
  are accepted only on the connection the matching request was sent on, within
  60 seconds. A pushed file closes the connection.
* **Verification before storing.** Only block archives are requested; they
  are decoded in memory, contain flat `<number>.blk` entries only, and every
  block is validated (seal, parent, state) by the node, whatever the seeds
  say. A pushed headers, summary, GVT or PSO file closes the connection.
* **`SETCFGDATA $<seq> <signature> <content>`** carries a signature over the
  whole configuration under the configured `ConfigKey`.
* **`ADMINMSG <seq> <expiryBlock> <text_with_underscores> <signature>`**; only
  configuration directives exist.
* **`MNVER <nonce>`** is a challenge; the answer is
  `True <synctus> <fund> <sign> <signPublicKey> <signature>`.
* **`$MNREPO`** has two more fields (fund public key and signature);
  **`$MNCHECK`** is signed under its own domain and only registered
  validators count.
* **Orders**: `TrfrID` is derived from the signed fields; signatures use
  SHA-256 over a canonical, length-prefixed encoding with low-S.
* **`NODESTATUS`** may end with ` SIG:<signature>` when the node has a sign
  key; consensus needs more than half of the configured, de-duplicated seeds.
* **Block archives** use entry names `N.blk`, not `NOSODATA/BLOCKS/N.blk`.
* Per-peer limits: 200 lines per 10 s (6000 for reports and orders, which
  answer `$GETMNS`/`$GETPENDING`), one file kind per 10 s (block requests: 1 s),
  `$GETMNS`, `$GETPENDING`, `GETMNSFILE` once per 10 s, 10 costly requests per
  minute, 64 accepted connections that are not peers yet.
