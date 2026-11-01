# Running a node

## Build

```sh
go build -o nosod ./cmd/nosod
go build -o nosocli ./cmd/nosocli
go build -tags gui -o nosogui ./cmd/nosogui   # needs a C compiler and the OpenGL/X11 development packages
```

Go 1.27.3 or newer.

## Start

```sh
export NOSO_WALLET_PASSPHRASE='at least 8 characters'    # or -wallet-pass-file FILE
./nosod -data NOSODATA
```

Options: `-wallet-pass-file` (or `NOSO_WALLET_PASSPHRASE`) for the wallet
passphrase, `-insecure-plain-wallet`, `-seed-url` (signed seed list, needs
`ReleaseKey`), `-no-p2p` (open the files and RPC only), `-no-ntp`, `-version`.
The wallet is encrypted; start without a passphrase and the node refuses to
run unless you explicitly allow the plain wallet. One process owns a data
directory: a second `nosod`, or a `nosocli` in offline mode beside a running
node, is refused.

On the first start the node creates the data directory, a wallet with one new
address, the genesis block, and `nosocfg.psk` with **no seeds**: the addresses
of the original network are not compiled in, so a fresh node connects to
nobody. Give it the nodes of the network you mean to join:

```sh
./nosocli -data NOSODATA addnode '203.0.113.5;8080'     # host;port, repeat for each node
```

The node dials every configured node (a node is a host and a port; several
may run on one machine), exchanges PINGs with them and asks any peer that
shows a longer chain, or another tip, for the blocks. Every block is checked
(proposer seal, signatures, state), whoever sends it; no vote of the seeds
decides anything about the chain. The log says `Updated!` when no connected
peer is ahead of the node (state 3). A node with one configured peer needs one
connection, a node with none is a standalone chain.

**Back up `NOSODATA/wallet.enc` and remember the passphrase.** The file holds
the private keys encrypted with Argon2id and AES-256-GCM; there is no
recovery without the passphrase.

Upgrading from the original node: with an old `wallet.pkw` in the data
directory the first start with a passphrase copies its keys into
`wallet.enc` after checking every key. The old `wallet.pkw` and its `.bak` are
left in place, so a mistyped passphrase loses nothing. They still hold the
keys in clear text: the start warns about it every time until you run
`nosocli wallet retire-legacy` (after backing up `wallet.enc`).

## Starting a network

A chain has a proposer list: `NOSODATA/proposers.txt`, one public key per line,
the same list in the same order on every node of the chain. A node builds only
if `BuildBlocks True` is set in `advopt.txt`, its wallet holds a key from the
list and it is that key's turn (`consensus.md`); its blocks are sealed with that
key and the block reward goes to that address. A node with no list accepts no
block from a peer.

**All on one machine** (or for a trial):

```sh
./nosod init-network -dir DEVNET -nodes 4 -proposers 3 [-host 127.0.0.1] [-bind ADDR] [-base-port 18080] [-rpc-base-port N]
```

creates `DEVNET/node1..node4`, each with its own wallet, the same
`proposers.txt` (the first three nodes), `nosocfg.psk` with the same seed list
on every node (all nodes, the node itself included, which never dials itself:
the nodes vote on the hash of their configuration, so lists that differ never
form a consensus and no masternode could be listed), `advopt.txt` with `Autoserver True`, `BuildBlocks True` for proposers,
its peer port (`base+i-1`) and RPC port, a `bind.txt`, a `network.txt` (the same on
every node: a random chain id and the `local_masternodes` rule, `yes` when `-host`
is loopback, `-local-masternodes yes|no` overrides) and random RPC tokens.
`-host` is the address the nodes tell each other; the peer listener binds
`-bind` (default: `-host`, so `127.0.0.1` keeps the network on this machine; a
plain `nosod` without `-bind` or `bind.txt` listens on every interface). The
RPC server always binds loopback. Peer ports are `base-port+i-1`; unless you
give `-rpc-base-port`, the RPC ports follow them (`base-port+nodes+i-1`).
Overlapping or out-of-range ports are refused before anything is written. It prints the
proposers' public keys, never a private key, and the `nosod -data ... -no-ntp`
line for each node. Start the nodes in any order; the server opens at start, no
console command is needed. Any number of nodes from 1 works (with one
proposer the others only follow).

**Across machines**: on each machine make the wallet (`nosocli newaddress`
or start `nosod` once), collect the proposers' public keys with
`nosocli pubkey` into one file (its `address key` lines are accepted as they
are) and run

```sh
./nosod init-network -data NOSODATA -proposer-keys proposers.txt -network-file network.txt -seed host1:8080 -seed host2:8080 [-propose]
```

(`network.txt` is copied from any node of the network. Without it the node uses the
default chain id and refuses the blocks of the network.)

which imports the keys, writes the seeds and `Autoserver True`, and with
`-propose` turns block building on (the first wallet key must be in the list).
Open the peer port. List every node of the network, this one included, with
`-seed`, and give all nodes the same list: the configuration hash is part of
the status the seeds vote on.

A test network can run faster than real time: `init-network -clock-scale N`
writes `devnet.txt` into the data directories and every node of that network
then runs its chain clock N times faster (N=200 gives a block every 3 seconds).
Only for networks nobody else connects to; the nodes skip NTP. The repository
test `cmd/nosod/TestNetworkOfProcesses` does exactly this with four processes.

Cut the node off from a peer, or restore it, at run time with
`nosocli denypeer host:port` / `allowpeer host:port|all` (used to test
partitions). Trust anchors have no defaults: set `AdminKey`, `ConfigKey`,
`ValidatorKeys` and `SeedKeys` yourself (public keys; see `compatibility.md`).

**RPC.** `RPCAuto True` starts the server on `127.0.0.1` (`rpcon` does it for a
running node); the tokens are in `advopt.txt`. See `rpc.md`.

## Becoming a masternode

1. Keep the stake on the funds address: 1050000 NOSO from block 110001; below
   that it is 0.2% of the supply (about 33 NOSO at block 120, the figure on a
   fresh test network). `consensus.GetStackRequired` is the exact rule.
2. `nosocli mnset <public ip> <port> <funds address> <sign address>` (the sign
   address is one of this wallet; or edit `MNIP`, `MNPort`, `MNFunds`,
   `MNSign` in `advopt.txt` with the node stopped).
3. The masternode sign address (`MNSign`) must not be a proposer's key: the node signs `MNVER` challenges for any peer that asks, and a proposer key never does that (such a masternode is not listed; `nosod` says so at start). `init-network` gives each proposer node a second address for it.
4. The address must be a public one: a report naming a loopback, private or documentation address is dropped (the node dials the address a report names). The one exception is a network whose `network.txt` sets `local_masternodes true` (`init-network` does so when `-host` is loopback): there loopback and private-use addresses (127/8, 10/8, 172.16/12, 192.168/16) are accepted, on every node alike, because the rule comes only from that file. At most one masternode can use one address. `TestLoopbackMasternodeIsListedAndPaid` runs a masternode on 127.0.0.1 with real processes, and `TestMasternodeIsListedOnEveryNode` does it in one process.
5. Open the TCP port; the server runs when `Autoserver True` is set.

The node reports itself every block between age 10 and 495. Every node that
receives the report checks its signature and stake and then challenges the IP
(`MNVER`, answered with the sign key) before it lists it. The funds key may stay
cold: on the machine with the funds key run
`nosocli mndelegate <funds address> <sign address>`, which prints
`<funds public key> <signature>` (never the private key); on the node that
holds the sign key run `nosocli mnsetdelegation <funds public key> <signature>`.

## Using the original's data

Stop the Pascal node and start `nosod -data <its NOSODATA>`. The files are
read as they are. Keep a copy first.

## Time

Peers refuse clocks that differ by more than 5 seconds (after block 70000).
`nosod` queries the SNTP servers of `nosocfg` field 2 at start and every ten
minutes.

## Testing without touching a network

There are no default seeds, so a node connects to nobody unless you wrote a
seed. `-no-p2p` opens the files and RPC without any networking; `-no-ntp`
skips the time servers (NTP is the one thing a default node reaches out for).
The test suite uses loopback only: `internal/network` starts four engines on
127.0.0.1 and `cmd/nosod` four processes.
