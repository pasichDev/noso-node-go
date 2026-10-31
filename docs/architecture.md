# Architecture

The code is split into small packages that depend downwards only. The Pascal
original keeps almost everything in global variables of one big form unit;
here the state lives in a `node.Node` value and a `network.Engine`.

```
cmd/nosod  cmd/nosocli  cmd/nosogui
        \       |        /
         internal/cli  (console commands)     internal/control (unix socket)
                |
         internal/rpc  (JSON-RPC)
                |
         internal/network  (peers, protocol, consensus polling, sync)
                |
         internal/node  (blocks, pool, masternodes, order validation)
                |
   internal/consensus  internal/storage  (files)
                |            |
         internal/types   internal/crypto
                |            |
              internal/codec
```

| Package | Responsibility | Original units |
|---|---|---|
| `codec` | Free Pascal behaviour: ShortString and little-endian record bytes, `Val`-style number parsing, the `Parameter` tokenizer | `nosogeneral` (Parameter, IsValidIP), FPC runtime |
| `crypto` | SHA-256, RIPEMD-160, MD5, Base58/Base36 conversions (including the signed big-integer quirk), lenient Base64, secp256k1 ECDSA with SHA-1, addresses, certificates | `nosocrypto`, `mpsignerutils` |
| `types` | Packed record layouts and the order text codec | records of `nosogeneral`, `nosounit`, `nosoblock`, `nosoheaders`, `nosogvts`, `nosowallcon`, `nosopsos` |
| `storage` | Every file under `NOSODATA`, the summary database with its per-block change list | `nosounit`, `nosoheaders`, `nosogvts`, `nosowallcon`, `nosonosocfg`, `nosomasternodes` (file part), `nosopsos`, `nosoblock`, `mpdisk` |
| `consensus` | Pure monetary rules: supply, reward, percentages, fees, block timing | `nosogeneral`, `mpblock.GetBlockReward`, `nosotime` |
| `node` | Block construction, summary replay, undo, the pending pool, order validation, masternode tables | `mpblock`, `mpdisk`, `mpprotocol` (validation), `mpcoin`, `nosomasternodes`, `nosonetwork` (pool) |
| `network` | Line and file framing, server and client roles, protocol dispatch, consensus polling, synchronisation state machine, SNTP | `nosonetwork`, `nosoconsensus`, `mpred`, `mpprotocol`, `masterpaskalform` (server and threads) |
| `rpc` | JSON-RPC server | `mprpc` |
| `cli` | Console commands | `mpparser` |
| `control` | Local socket between `nosocli` and `nosod` | none (new) |

## Concurrency

The original uses threads and critical sections. This port uses goroutines
and mutexes with the same granularity: one mutex per data structure
(`SummaryDB`, headers, GVTs, wallet, pool, masternode tables, peer table).
The heartbeat (`Engine.Tick`, every 200 ms) is the equivalent of the
`Latido` timer; the keep-connect loop, the masternode worker, the consensus
poller and the block-time timer run as separate goroutines.

## What a block cycle looks like

1. The timer sets the next build time to the next multiple of 600 seconds.
2. When the node is in state 3 (updated) and its last block equals the
   consensus last block, the heartbeat calls `Node.BuildNewBlock`.
3. The block is written, the summary and headers files are updated, a PING is
   broadcast, peers compare hashes and the consensus converges.
4. A node that is behind asks a synced peer for headers, blocks and, when its
   summary hash differs after replay, the whole summary.

There is no mining in this protocol (version 0.4.4): every node builds the
block itself and agreement is checked by comparing hashes.
