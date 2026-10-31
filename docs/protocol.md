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
`Closing NODE` (node not yet in state 3 and caller is not a seed node, or the
server is being closed).

### Peer connection

A line starting with `PSK ` registers a peer: `PSK <yourIP> <version> <utc>`.
After the checks below the connection becomes a `CLI` slot (they dialled us);
connections we dial are `SER` slots. In order:

1. not starting with `PSK ` -> `WRONG_PROTOCOL` and the IP is remembered as a bot
2. the caller is our own public IP -> closed
3. time difference above 5 s (only when our last block is at least 70000) -> `WRONG_TIME`
4. IP already has a slot -> `PSK 2 0.4.4Ab9 <utc> DUPLICATED`, bot entry
5. peer version (first 3 characters) below `0.4` -> `... OLDVERSION->REQUIRED_0.4.4`
6. no free slot (99 maximum) -> closed

The dialling side sends `PSK <serverAddress> 0.4.4Ab9 <utc>` and then a PING.

## Protocol lines

`PSK 2 <version> <utc> <command> <args...>`; fields are blank separated and
read with the `Parameter` tokenizer (parentheses group text). COMPAT: lines
built by `ProtocolLine` advertise the version as `0.4.4zzz`, lines built by
`GetPTCEcn` advertise `0.4.4Ab9`.

| Command | Sent when | Meaning |
|---|---|---|
| `$PING` / `$PONG` | every 5 s, after a block, on connect | node state, see below |
| `$GETPENDING` | state 3 and peers have more pending | answer: `ORDER` lines and `$CUSTOM`/`$SNDGVT` lines |
| `$GETRESUMEN` | headers hash differs | answer: `RESUMENFILE` |
| `GETHEADUPDATE n` | fewer than 144 blocks behind | answer: `HEADUPDATE $b:hash:sum b:hash:sum ...` |
| `$LASTBLOCK n` | blocks missing | answer: `BLOCKZIP` with blocks n+1..n+101 (peer path) or n..n+100 (server path), see compatibility |
| `$GETSUMARY` | summary differs | answer: `SUMARYFILE` |
| `$GETGVTS`, `$GETPSOS` | hash differs | `GVTSFILE`, `PSOSFILE` |
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

## Consensus

Every minute (block age 5-584 s) the node asks `NODESTATUS` to each seed in
`nosocfg` field 1. The consensus hash of a node is `MD5(lastBlock + headers5 +
mns5 + lastBlockHash5 + summary5 + gvt5 + cfg5)`. The most frequent hash wins
(first on ties); then, parameter by parameter, the most frequent value among
the nodes that agree with the winner. Item 0 is the hash itself and item N
is NODESTATUS parameter N.

## Connection state machine

* 0: no peers. 1: connecting (1 or 2 peers). 2: connected (3 or more).
  3: updated (my last block, summary 5-char hash and headers 5-char hash
  equal the consensus).
* Only state 3 nodes answer non-seed peers. A node in state 3 builds blocks.
* `SyncWithMainnet` (every 4 s, block age 10-595) requests, throttled to one
  request per kind every 5-15 s: nosocfg, masternodes file, headers (full
  file if 144 or more behind, otherwise an update), blocks, summary (or
  replays blocks when within 200 of the head), GVTs, PSOs, masternode
  reports, masternode checks. If the last block hash or headers disagree with
  consensus it **undoes the last block**.

## Time

Block boundaries are multiples of 600 seconds of UTC time corrected by an
SNTP offset. The first 10 and last 15 seconds of a period ("block closed")
are ignored by most protocol handlers.

## Changes from the original protocol (security fixes)

The port deliberately departs from the Pascal wire protocol where
`SECURITY_REVIEW.md` found vulnerabilities (details and tests in
[compatibility.md](compatibility.md)). A Pascal node and this node do not
fully interoperate.

* **Files and configuration are answers only.** `RESUMENFILE`, `SUMARYFILE`,
  `GVTSFILE`, `PSOSFILE`, `BLOCKZIP`, `MNFILE`, `HEADUPDATE` and `SETCFGDATA`
  are accepted only on the connection the matching request was sent on, within
  60 seconds. A pushed file closes the connection.
* **Verification before storing.** Headers, summary and GVT files must hash
  (`IDHash`, 128 bits of SHA-256) to the value the peer advertised in its
  PING and to the consensus prefix; block archives are decoded in memory,
  contain flat `<number>.blk` entries only, and every block is validated
  against its parent.
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
* Per-peer limits: 200 lines per 10 s, one file kind per 10 s, 10 costly
  requests per minute.
