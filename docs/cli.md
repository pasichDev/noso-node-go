# Command line (`nosocli`)

```
nosocli [-data DIR] [-echo] <command> [arguments]
nosocli -list
```

Without a command, `nosocli` reads commands from standard input. It first
tries the control socket of a running `nosod` in the same data directory
(`DIR/nosod.sock`, mode 0600; very long directory names use a short name in
the temp directory). If there is none, it opens the data directory itself
("offline mode"): wallet, chain and hash commands work, network commands say
that they need a running node.

Offline mode takes the exclusive lock of the data directory first. If a daemon
(or the GUI, which also serves a control socket) holds the directory, `nosocli`
refuses with a message instead of becoming a second writer of the wallet and
chain files. Status-style commands (`status`, `balance`, `showwallet`,
`pubkey`, ...) open the wallet read-only.

Commands are case insensitive; arguments are blank separated. The list below
is the dispatch table of the original `ParseCommandLine`; `nosocli -list`
prints the exact set.

| Group | Commands |
|---|---|
| General | `ver`, `status`, `timestamp`, `osversion`, `offset`, `useroptions`, `saveadv`, `restart`, `myhash`, `system power\|mem\|downspeed` |
| Network | `serveron`, `serveroff`, `forceserver` (not needed: `Autoserver True` opens the server at start), `nodes`, `bots`, `delbots`, `connectto ip [port]`, `disconnect`, `denypeer host:port` (close, refuse and do not dial; no argument lists), `allowpeer host:port\|all`, `myip`, `peers`, `autoserveron`, `autoserveroff`, `consensus`, `constats`, `isallsynced` |
| Wallet | `newaddress`, `balance`, `showwallet`, `impwallet file`, `expwallet name`, `setdefault addr`, `showkeys addr`, `expkeys addr`, `webwal`, `exportaddress addr`, `newfromkeys pub priv`, `validate addr`, `pubkey [addr]` (address and public key only), `wallet [retire-legacy]`, `getcert addr`, `checkcert cert`, `getmulti n,m addrs`, `customize addr alias`, `sendto dest amount [reference]` (amount in NOSO, `Nu` for base units), `sendgvt n dest` |
| Chain | `lbinfo`, `block n`, `resumen [n]`, `headsize`, `order id`, `ordersources id`, `ordinfo id`, `address addr\|alias`, `history addr [blocks]`, `totalfees`, `supply`, `halving`, `getpos [n]`, `getmns [n]`, `gmts amount`, `sumary`, `sumindexsize`, `funds`, `freezed`, `pending`, `blockpos n`, `blockmns n`, `getdblb` |
| GVT | `listgvt`, `gvtinfo` |
| Masternodes | `mnschecks`, `tt`, `mnset ip port funds sign`, `mndelegate funds sign`, `mnsetdelegation fundsPub signature` |
| Hashes | `sha256 text`, `md5 text`, `md160 text`, `base58sum text`, `addfrompub key`, `testhash n`, `compare key` |
| Config | `nosocfg`, `setmode`, `addnode`, `delnode`, `addpool`, `delpool`, `addnosopay`, `delnosopay`, `restorecfg`, `clearcfg n`, `getreposeeds`, `forcereposeeds`, `directive text` |
| RPC | `rpcon`, `rpcoff`, `setrpcport port` |
| Maintenance | `undoblock`, `rebuildsum`, `zipsumary`, `restoresumary`, `restoreblockchain confirm` (deletes the chain and everything derived from it; only in a program that can restart the node, i.e. `nosod`), `testhead` |
| PSO | `listpsos`, `showpsos` (`newpso`, `clearpsos` were removed) |
| Other | `tp`, `post`, `clear`, `closestarton`, `closestartoff`, `setport`, `showpending` |
| Not supported | `update`, `getbeta`, `checkupdates`, `sendreport`, `testnet` (see port-status) |

**Amounts.** `sendto` takes NOSO: `sendto dest 10`, `sendto dest 1.5`,
`sendto dest 0.00000001` (up to 8 decimals, converted exactly). A trailing `u`
gives base units: `sendto dest 150000000u` is 1.5 NOSO (1 NOSO = 100000000
units). Balances are printed in NOSO. The RPC method `sendfunds` takes base
units only (see `rpc.md`).

**Exit codes.** `nosocli` exits 0 when the command succeeded and 1 when it
failed: an unknown command, an invalid argument, a refused order, no daemon
and no data directory. `-data` must point at an existing node directory (a
wallet, `advopt.txt` or `BLOCKS` in it) or a running node; otherwise nothing is
created and it exits 1. `-create` starts a new data directory on purpose.

**Keys over the socket.** `showkeys`, `expkeys`, `expwallet`, `exportaddress`,
`signcfg` and `directive` through a running node's control socket need the
wallet passphrase as proof (`NOSO_WALLET_PASSPHRASE` or `-wallet-pass-file` for
`nosocli`): any process of your user can reach the socket. Offline, with the
node stopped, the passphrase opened the wallet already.

**Not commands any more.** `newpso` and `clearpsos` changed the PSO file of one
node only, which then refused the next block (the PSO file is in the state
root); blocks carry no PSO, so none can be created and the commands answer
with that reason. `restorecfg` restores the
defaults but keeps the seed list; `restorecfg seeds` resets that too (this
build has no default seeds, the node then has no peers). `customize` checks
the real balance of the address. `sendgvt n dest` signs the canonical number
and the order reaches the pool and the peers (`$SNDGVT`).

`sendto` builds the order exactly like the original: it tries your wallet
addresses starting with the first one, signs, hands the line (rewritten to
start with `NSLORDER`) to a synced peer and also broadcasts it.

## Differences (security fixes)

* `update`, `getbeta`, `checkupdates`, `sendreport` and `testnet` were removed.
* `getcert address audience nonce`, `checkcert certificate audience nonce`.
* `directive sequence expiryBlock text` and `signcfg sequence` need the
  private key of the configured `AdminKey` / `ConfigKey` in the wallet.
* `showkeys`, `expkeys`, `newfromkeys`, `signcfg` and `directive` are never
  echoed or logged.
* `getreposeeds url` / `forcereposeeds url` use an https URL and a detached
  signature under `ReleaseKey`.
* The wallet needs a passphrase: `NOSO_WALLET_PASSPHRASE` or
  `-wallet-pass-file`; `-insecure-plain-wallet` keeps the old clear-text file.
