# Progress (delete when done)

Scope change received mid-task: Fyne GUI (cmd/nosogui) is now in scope, last stage, thin layer over core packages.

- [x] crypto (hashes, base conversions, secp256k1 SHA1-ECDSA, addresses, certificates)
- [x] codec text helpers (Parameter, Val-style parsing)
- [x] codec/types records
- [x] storage
- [x] consensus (rules + node engine: blocks, pool, masternodes, summary rebuild)
- [x] network (server, client, framing, consensus, sync, MN worker, SNTP; loopback test)
- [x] rpc
- [x] cli (dispatcher, nosod, nosocli, control socket)
- [x] security fixes (stage added after rpc, before cli): all 43 findings of SECURITY_REVIEW.md, see docs/compatibility.md
- [ ] docs (core docs written; port-status.md pending)
- [ ] gui
