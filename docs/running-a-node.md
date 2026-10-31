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
./nosod -data NOSODATA
```

Options: `-wallet-pass-file` (or `NOSO_WALLET_PASSPHRASE`) for the wallet
passphrase, `-insecure-plain-wallet`, `-seed-url` (signed seed list, needs
`ReleaseKey`), `-no-p2p` (open the files and RPC only), `-no-ntp`, `-version`.
The wallet is encrypted; start without a passphrase and the node refuses to
run unless you explicitly allow the plain wallet.

On the first start the node creates the data directory, a wallet with one new
address, the genesis block, and `nosocfg.psk` with the default seeds. It then
synchronises: it needs at least 3 peers, learns the consensus from the seed
nodes and downloads headers, blocks and, if needed, the summary. When the log
says `Updated!` the node is in state 3.

**Back up `NOSODATA/wallet.enc` and remember the passphrase.** The file holds
the private keys encrypted with Argon2id and AES-256-GCM; there is no
recovery without the passphrase.

**Who builds blocks.** By default a node only follows the chain. Exactly the
nodes you configure as proposers set `BuildBlocks True` in `advopt.txt`.
Trust anchors have no defaults: set `AdminKey`, `ConfigKey`, `ValidatorKeys`
and `SeedKeys` yourself (public keys; see `compatibility.md`).

**RPC.** `rpcon` starts the server on `127.0.0.1`; the tokens are in
`advopt.txt`.

## Becoming a masternode

1. Keep at least 1050000 NOSO (the stack) on the funds address.
2. Edit `advopt.txt` (stop the node first, or use `nosocli`): `MNIP` your
   public IP (or `MNAutoIp True`), `MNPort 8080`, `MNFunds` the funds
   address, `MNSign` a wallet address of this node.
3. Open the TCP port, run `serveron` (or `Autoserver True`).

The node reports itself every block between age 10 and 495, and the seed
nodes verify it.

## Using the original's data

Stop the Pascal node and start `nosod -data <its NOSODATA>`. The files are
read as they are. Keep a copy first.

## Time

Peers refuse clocks that differ by more than 5 seconds (after block 70000).
`nosod` queries the SNTP servers of `nosocfg` field 2 at start and every ten
minutes.

## Not connecting to the main network while testing

Use `-no-p2p`, or put your own seed in `nosocfg.psk` and start with
`-no-seed-download`. The test suite never touches the network; the loopback
test starts two nodes on 127.0.0.1.
