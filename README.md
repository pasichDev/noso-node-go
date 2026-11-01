<p align="center">
  <img src="docs/assets/noso-logo.png" alt="Noso coin logo" width="128" height="128">
</p>

<h1 align="center">noso-node-go</h1>

<p align="center">
  A Go node for the Noso coin: daemon, command line and desktop wallet.
</p>

<p align="center">
  <a href="https://github.com/pasichDev/noso-node-go/actions/workflows/ci.yml"><img src="https://github.com/pasichDev/noso-node-go/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Unlicense-blue.svg" alt="License: Unlicense"></a>
  <img src="https://img.shields.io/badge/go-1.27.3-00ADD8.svg?logo=go&logoColor=white" alt="Go 1.27.3">
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Status: experimental">
</p>

noso-node-go is a Go rewrite of the Free Pascal Noso node. It keeps the original
file formats and the rules for balances, orders and rewards. The original public
network is inactive, so this node does not try to join it. It runs **its own
networks**, whose blocks are sealed by a fixed list of proposers
([consensus](docs/consensus.md)). No peer address is compiled in; a node connects
to the seeds you give it.

> **Independent and unofficial.** This project is not made, endorsed or supported
> by the Noso project or its developers. The logo belongs to the original project,
> whose repository is at <https://github.com/nosocoin/NosoNode>.
> This software is experimental and has had no independent security audit. Do not
> use it to hold anything of value.

## Project status

| Area | State |
|---|---|
| Local multi-node network | Works: four real processes reach one chain of 50 blocks, with an order over RPC, a restart and a healed partition |
| Chain from genesis | A real chain crosses block 8428 and syncs to a second node; blocks 48010 and 88500 are covered only with a synthetic fast-forward |
| Wallet | Encrypted by default, with migration from `wallet.pkw` |
| Desktop app | Exercised with the Fyne test driver only; not clicked through by hand |
| Windows | Builds; never run |
| Pascal nodes | Blocks and several messages differ, see [compatibility](docs/compatibility.md); never tested against a running Pascal node |
| Security | 43 findings of the original are tracked in [SECURITY_REVIEW.md](SECURITY_REVIEW.md); internal review only |

Consensus is proof of authority: a proposer on the list can censor orders or sign
two blocks for one slot, and a heavier branch can rewrite history. Blocks and
wallets may change without a migration path until a first release.

## What is in the box

| Program | What it does |
|---|---|
| `nosod` | The node daemon: peer-to-peer server and client, block builder, JSON-RPC server, local control socket. |
| `nosocli` | The console commands of the original node as a command line tool. Talks to a running `nosod`, or works on the data directory directly when none is running. |
| `nosogui` | A desktop front end (Fyne 2.8) that uses the same packages as the other two. Built with `-tags gui`; needs a C compiler and OpenGL/X11 headers. See [port status](docs/port-status.md) for what each screen has been verified with. |

All three use the same data directory layout as the original (`NOSODATA/`):
`sumary.psk`, `blchhead.nos`, `gvts.psk`, `nosocfg.psk`, `masternodes.txt`,
`wallet.enc`, `psos.dat`, `advopt.txt`, `BLOCKS/*.blk`. A `wallet.pkw` from a
Pascal node is migrated, and the original file is kept until you retire it.

## Quick start

A network of four nodes (three of them build blocks) on this machine, built
and started from this page alone:

```sh
go build -o nosod ./cmd/nosod
go build -o nosocli ./cmd/nosocli

export NOSO_WALLET_PASSPHRASE='choose a passphrase of 8 or more characters'
./nosod init-network -dir DEVNET -nodes 4 -proposers 3     # wallets, proposers.txt, seeds, ports
# in four shells (the same passphrase in each); -bind keeps the peer listener on loopback
./nosod -data DEVNET/node1 -no-ntp -bind 127.0.0.1
./nosod -data DEVNET/node2 -no-ntp -bind 127.0.0.1
./nosod -data DEVNET/node3 -no-ntp -bind 127.0.0.1
./nosod -data DEVNET/node4 -no-ntp -bind 127.0.0.1

./nosocli -data DEVNET/node1 status          # talks to the running node
./nosocli -data DEVNET/node1 pubkey          # address and public key, never the private key
# the first block comes at the next ten-minute boundary and its reward is the first
# spendable coin; then, from node 4 (it builds nothing) to any address:
./nosocli -data DEVNET/node4 sendto N3DthVsfEUtqrgWFHTEB6F88xLkT3Df 1.5   # amounts are NOSO
./nosocli -data DEVNET/node4 balance
```

`init-network` writes `bind.txt` into each data directory (its `-host`, loopback
by default), so a network made by it stays on this machine even without
`-bind`; a node started on its own listens on every interface unless you give
`-bind`. Its default ports for N nodes are peers `18080..` and RPC right after
them (`18080+N..`); ports that overlap are refused.

`init-network` prints the public keys of the proposers and the command to start
every node; any number of nodes from one works. A single node on its own is
`./nosod -data NOSODATA` (it needs the passphrase too, and connects to nobody
until you give it seeds with `nosocli addnode 'host;port'`). The block clock of a
network runs in real time (a block every ten minutes); `-clock-scale` makes a
test network faster, see [docs/running-a-node.md](docs/running-a-node.md).

See [docs/running-a-node.md](docs/running-a-node.md) for the full guide.

## Documentation

- [Architecture](docs/architecture.md): packages and how they fit together
- [Protocol](docs/protocol.md): the peer-to-peer wire protocol
- [Storage](docs/storage.md): every file and its byte layout
- [Consensus](docs/consensus.md): blocks, rewards, masternodes, summary rebuild
- [Crypto](docs/crypto.md): hashes, addresses, signatures and their quirks
- [RPC](docs/rpc.md): the JSON-RPC API
- [CLI](docs/cli.md): console commands
- [Running a node](docs/running-a-node.md)
- [Compatibility](docs/compatibility.md): preserved original bugs, hardening, and what could not be verified
- [Port status](docs/port-status.md): every original unit and routine, ported or not, and why

## Security status

A security review of the original (`SECURITY_REVIEW.md`, 43 findings) is
worked through in this port; the status column of that file says per finding
what is fixed, what is only partly fixed and what is open. The fixes
deliberately break compatibility with unmodified Pascal nodes where they must:
signed message formats, the wallet file, RPC access, update handling and
several protocol messages. The network is inactive, so this was chosen over
byte-for-byte preservation for those findings only. The table in
[docs/compatibility.md](docs/compatibility.md) lists the fixes. Trust keys
(admin, configuration, validators, seeds, release) and peer addresses have no
defaults and must be configured.

## Compatibility promise and its limit

The goal is byte-for-byte compatibility of file formats, framing and rules
that no security finding touches. Behaviour of the original that affects
consensus or the wire protocol is kept even when it looks like a bug, unless
a security finding required a change; those places are marked `// COMPAT:`
and `// FIX(<id>):` in the code and listed in
[docs/compatibility.md](docs/compatibility.md).

What has **not** been proven: this port has never been connected to the real
network and was never compared to a running Pascal node, because the Pascal
compiler was not available and the network is gone. What is tested end to end
is its own network: `cmd/nosod` starts four `nosod` processes on loopback,
places an order over RPC, restarts a node, cuts the network in two and heals
it, and checks that all nodes hold one chain of 50 blocks. The test suite uses real data files from the original repository and
values derived by hand from the Pascal source. The limits are spelled out in
the compatibility document.

## Credits and license

The Noso protocol, the original node and its documentation were written by the
Noso project authors (<https://github.com/nosocoin/NosoNode>). This port reads
their source code as a specification and would not exist without it. The
cryptography in the original uses libraries by Xor-el (CryptoLib4Pascal,
HashLib4Pascal, SimpleBaseLib).

This project is released under the Unlicense, the same as the original; see
[LICENSE](LICENSE). The test data files under `testdata/` are copied from the
original repository (also Unlicense).
