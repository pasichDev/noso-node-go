# noso-node-go

A Go implementation of the Noso cryptocurrency node. It reads and writes the
file formats of the original Free Pascal node and keeps its rules for balances,
orders and rewards. The original public network is inactive, so this port does
not try to join it: it runs **its own networks**, whose blocks are sealed by a
list of proposers (see [docs/consensus.md](docs/consensus.md)). No peer address
is compiled in; a node connects to the seeds you write for it.

> **This is an independent, unofficial port.** It is not made, endorsed or
> supported by the Noso project or its developers. The original node lives at
> <https://github.com/nosocoin/NosoNode>. Use this software at your own risk,
> and do not keep funds on a wallet you have not backed up.

## What is in the box

| Program | What it does |
|---|---|
| `nosod` | The node daemon: peer-to-peer server and client, block builder, JSON-RPC server, local control socket. |
| `nosocli` | The console commands of the original node as a command line tool. Talks to a running `nosod`, or works on the data directory directly when none is running. |
| `nosogui` | A desktop front end (Fyne 2.8) that uses the same packages as the other two. Built with `-tags gui`; needs a C compiler and OpenGL/X11 headers. Not visually verified, see docs/port-status.md. |

All three use the same data directory layout as the original (`NOSODATA/`):
`sumary.psk`, `blchhead.nos`, `gvts.psk`, `nosocfg.psk`, `masternodes.txt`,
`wallet.pkw`, `psos.dat`, `advopt.txt`, `BLOCKS/*.blk`. You can point `nosod`
at the data directory of a Pascal node (stop that node first).

## Quick start

A network of four nodes (three of them build blocks) on this machine, built
and started from this page alone:

```sh
go build -o nosod ./cmd/nosod
go build -o nosocli ./cmd/nosocli

export NOSO_WALLET_PASSPHRASE='choose a passphrase of 8 or more characters'
./nosod init-network -dir DEVNET -nodes 4 -proposers 3     # wallets, proposers.txt, seeds, ports
# in four shells (the same passphrase in each):
./nosod -data DEVNET/node1 -no-ntp
./nosod -data DEVNET/node2 -no-ntp
./nosod -data DEVNET/node3 -no-ntp
./nosod -data DEVNET/node4 -no-ntp

./nosocli -data DEVNET/node1 status          # talks to the running node
./nosocli -data DEVNET/node1 pubkey          # address and public key, never the private key
```

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
