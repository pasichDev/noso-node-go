# noso-node-go

A Go implementation of the Noso cryptocurrency node. It is meant to join the
existing Noso network next to the original Free Pascal node and arrive at the
same state: same files on disk, same blocks, same balances, same network
messages.

> **This is an independent, unofficial port.** It is not made, endorsed or
> supported by the Noso project or its developers. The original node lives at
> <https://github.com/nosocoin/NosoNode>. Use this software at your own risk,
> and do not keep funds on a wallet you have not backed up.

## What is in the box

| Program | What it does |
|---|---|
| `nosod` | The node daemon: peer-to-peer server and client, block builder, JSON-RPC server, local control socket. |
| `nosocli` | The console commands of the original node as a command line tool. Talks to a running `nosod`, or works on the data directory directly when none is running. |
| `nosogui` | A desktop front end (Fyne) that uses the same packages as the other two. Built with `-tags gui`. |

All three use the same data directory layout as the original (`NOSODATA/`):
`sumary.psk`, `blchhead.nos`, `gvts.psk`, `nosocfg.psk`, `masternodes.txt`,
`wallet.pkw`, `psos.dat`, `advopt.txt`, `BLOCKS/*.blk`. You can point `nosod`
at the data directory of a Pascal node (stop that node first).

## Quick start

```sh
go build -o nosod ./cmd/nosod
go build -o nosocli ./cmd/nosocli

./nosod -data NOSODATA            # starts the node
./nosocli -data NOSODATA status   # in another shell
./nosocli -data NOSODATA rpcon    # turn on the JSON-RPC server on port 8078
```

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
addressed in this port, and the fixes deliberately break compatibility with
unmodified Pascal nodes where they must: signed message formats, the wallet
file, RPC access, update handling and several protocol messages. The network
is inactive, so this was chosen over byte-for-byte preservation for those
findings only. The table in [docs/compatibility.md](docs/compatibility.md)
lists every fix, whether it breaks interoperability, and its regression test.
Trust keys (admin, configuration, validators, seeds, release) have no defaults
and must be configured.

## Compatibility promise and its limit

The goal is byte-for-byte compatibility of file formats, framing and rules
that no security finding touches. Behaviour of the original that affects
consensus or the wire protocol is kept even when it looks like a bug, unless
a security finding required a change; those places are marked `// COMPAT:`
and `// FIX(<id>):` in the code and listed in
[docs/compatibility.md](docs/compatibility.md).

What has **not** been proven: this port has never been connected to the real
network and was never compared to a running Pascal node, because the Pascal
compiler was not available and connecting to the live network was out of
scope. The test suite uses real data files from the original repository and
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
