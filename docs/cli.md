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

Do not use offline mode on a data directory that a daemon is using without a
control socket.

Commands are case insensitive; arguments are blank separated. The list below
is the dispatch table of the original `ParseCommandLine`; `nosocli -list`
prints the exact set.

| Group | Commands |
|---|---|
| General | `ver`, `status`, `timestamp`, `osversion`, `offset`, `useroptions`, `saveadv`, `restart`, `myhash`, `system power\|mem\|downspeed` |
| Network | `serveron`, `serveroff`, `forceserver`, `nodes`, `bots`, `delbots`, `connectto ip [port]`, `disconnect`, `myip`, `peers`, `autoserveron`, `autoserveroff`, `consensus`, `constats`, `isallsynced` |
| Wallet | `newaddress`, `balance`, `showwallet`, `impwallet file`, `expwallet name`, `setdefault addr`, `showkeys addr`, `expkeys addr`, `webwal`, `exportaddress addr`, `newfromkeys pub priv`, `validate addr`, `getcert addr`, `checkcert cert`, `getmulti n,m addrs`, `customize addr alias`, `sendto dest amount [reference]`, `sendgvt n dest` |
| Chain | `lbinfo`, `block n`, `resumen [n]`, `headsize`, `order id`, `ordersources id`, `ordinfo id`, `address addr\|alias`, `history addr [blocks]`, `totalfees`, `supply`, `halving`, `getpos [n]`, `getmns [n]`, `gmts amount`, `sumary`, `sumindexsize`, `funds`, `freezed`, `pending`, `blockpos n`, `blockmns n`, `getdblb` |
| GVT | `listgvt`, `gvtinfo` |
| Masternodes | `mnschecks`, `tt` |
| Hashes | `sha256 text`, `md5 text`, `md160 text`, `base58sum text`, `addfrompub key`, `testhash n`, `compare key` |
| Config | `nosocfg`, `setmode`, `addnode`, `delnode`, `addpool`, `delpool`, `addnosopay`, `delnosopay`, `restorecfg`, `clearcfg n`, `getreposeeds`, `forcereposeeds`, `directive text` |
| RPC | `rpcon`, `rpcoff`, `setrpcport port` |
| Maintenance | `undoblock`, `rebuildsum`, `zipsumary`, `restoresumary`, `restoreblockchain`, `testhead` |
| PSO | `newpso`, `listpsos`, `clearpsos`, `showpsos` |
| Other | `tp`, `post`, `clear`, `closestarton`, `closestartoff`, `setport`, `showpending` |
| Not supported | `update`, `getbeta`, `checkupdates`, `sendreport`, `testnet` (see port-status) |

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
