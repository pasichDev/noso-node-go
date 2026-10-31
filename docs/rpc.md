# JSON-RPC

Enable with `rpcon` (or `RPCAuto True` in `advopt.txt`). Default port 8078.
Plain HTTP `POST` with a JSON-RPC 2.0 body. The response is always HTTP 200
with content type `text/html`, like the original.

* Access filter: when `RPCFilter` is on, the caller IP must be in
  `RPCWhiteList` (default `127.0.0.1,localhost`); otherwise error 498.
* A non-POST request gets error 400.
* Methods listed in `RPCBanned` (substring test) answer `banned`.
* Errors: `{"jsonrpc":"2.0","error":{"code":N,"message":"..."},"id":-1}` with
  400 Bad Request, 401 Invalid JSON request, 402 Invalid method, 407 Send
  funds failed, 498 Not authorized, 499 Unexpected error.
* COMPAT: valid JSON missing `method`, `params` or an integer `id` gives an
  **empty body** (the original swallows the exception).
* Success: `{"jsonrpc":"2.0","result":[ {...}, ... ],"id":N}`; `result` is an
  array with one object per record. Strings are escaped like FPC JSON: `/` is
  `\/`, non-ASCII is `\uXXXX`.
* The parameters array is joined with blanks and re-split, so parameters
  cannot contain blanks.

| Method | Params | Result objects |
|---|---|---|
| `test` | | `{"result":"testok"}` |
| `restart` | | `{"result":"True"}`; nosod closes and reopens the node in the same process. Front ends that cannot restart (the GUI) answer `Invalid method` |
| `getaddressbalance` | addresses or aliases | `{"valid","address","alias","balance","incoming","outgoing"}`; unknown address: `valid:false, alias:null, -1` values; an unknown *alias* is silently skipped |
| `getorderinfo` | order id | `{"valid","order":{"orderid","timestamp","block","type","trfrs","receiver","amount","fee","reference","sender"}}` (orders already mined are found only with `BlocksDB True`) |
| `getblocksinfo` | block numbers | `{"valid","number","timestart","timeend","timetotal","last20","totaltransactions","difficulty","target","solution","lastblockhash","nextdifficult","miner","feespaid","reward","hash"}` |
| `getmainnetinfo` | | `{"lastblock","lastblockhash","headershash","sumaryhash","pending","supply"}` (from the consensus) |
| `getpendingorders` | | `{"pendings":[...]}` of `id,time,type,from,to,amount,fee,reference` |
| `lockedmns` | | `{"lockedmns":[...]}` of `address,expire` |
| `getpeers` | | `{"peers":[...]}` |
| `getblockorders` | block | `{"valid","block","orders":[...]}` grouped by order id |
| `getblockmns` | block | `{"valid","block","count","reward","total","addresses"}` |
| `getmasternodes` | | `{"block","count","nodes":"[ip,port,address,age]..."}` |
| `getwalletbalance` | | `{"balance"}` |
| `getnewaddress` | count (max 100) | `{"addresses":[...]}` |
| `getnewaddressfull` | | `{"hash","public","private"}` |
| `islocaladdress` | address | `{"result":bool}` |
| `setdefault` | address | `{"result":bool}` |
| `getgvtinfo` | | `{"available","buy","sell"}` |
| `sendfunds` | destination amount [reference] | `{"valid":true,"result":"OR..."}` or `{"valid":false,"result":code}` |
| `checkcertificate` | certificate | `{"valid":true,"address","signtime"}` or `{"valid":false}` |
| `submitorder` | order text | `{"result":true}` |
| `submitorderwr` | order text | `{"result":true,"response":"..."}` |

## Access control (security fixes, H-09)

* The server listens on `127.0.0.1` unless `RPCBind` says otherwise.
* Every request needs `Authorization: Bearer <token>`: `RPCToken` (read
  methods) or `RPCSpendToken` (also `sendfunds`, `submitorder`,
  `submitorderwr`, `setdefault`, `getnewaddress`, `getnewaddressfull`,
  `restart`). Both are generated randomly on first start and stored in
  `advopt.txt` (mode 0600); the old default password is gone.
* Requests with an `Origin` header, or a content type other than
  `application/json`, are refused.
* `getnewaddressfull` returns an empty `private` unless `RPCExposeKeys True`.
* `checkcertificate` takes `certificate audience nonce`.
