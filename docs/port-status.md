# Port status

Every unit of the original source and every public routine, with its fate.
Status values: **ported** (same behaviour), **changed** (ported, deliberately
different because of a security finding, see [compatibility.md](compatibility.md)),
**skipped** (not ported, reason given), **GUI** (handled by `cmd/nosogui`, see
the GUI section at the end).

Go locations are in `internal/` unless noted.

## Units of `Noso.lpr` and others

| Unit | Status | Where / reason |
|---|---|---|
| `nosocrypto` | ported / changed | `crypto` |
| `mpsignerutils` | ported / changed | `crypto` (`sign.go`, `secp256k1.go`) |
| `nosogeneral` | ported | `codec`, `consensus`, `types`, `storage`, `network/ops.go` |
| `nosotime` | ported / changed | `consensus` (block timing), `network/run.go` (SNTP), `node` (clock) |
| `nosodebug` | ported (reduced) | logging in `logx` and the `Log` hooks; performance counters, thread and file-process tables skipped (diagnostics only) |
| `nosounit` | ported / changed | `storage/summary.go`, `node/block.go` |
| `nosoheaders` | ported | `storage/headers.go` |
| `nosogvts` | ported | `storage/gvts.go` |
| `nosonosocfg` | ported | `storage/cfg.go` |
| `nosopsos` | ported | `storage/psos.go` |
| `nosowallcon` | ported / changed | `storage/wallet.go`, `storage/walletenc.go` |
| `nosoblock` | ported | `storage/blocks.go`, `storage/blocksdb.go`, `node/zip.go` |
| `nosoconsensus` | ported / changed | `network/consensus.go` |
| `nosomasternodes` | ported / changed | `node/mn.go`, `storage/masternodes.go`, `network/run.go` |
| `nosonetwork` | ported / changed | `network/*`, `node/pool.go` |
| `nosoipcontrol` | ported | `network/engine.go` (`AddIPControl`, `ClearIPControls`) |
| `nosoclient` | skipped | empty unit (14 lines, no code) |
| `mpblock` | ported / changed | `node/block.go`, `consensus/rules.go` |
| `mpcoin` | ported / changed | `node/pool.go`, `node/orders.go`, `network/ops.go` |
| `mpdisk` | ported / changed | `node/node.go`, `node/block.go`, `storage/options.go` |
| `mpparser` | ported / changed | `cli` |
| `mpprotocol` | ported / changed | `network/protocol.go`, `node/pool.go` |
| `mpred` | ported / changed | `network/*` |
| `mprpc` | ported / changed | `rpc` |
| `mpsyscheck` | ported | `cli/commands2.go` (`system power|mem|downspeed`) |
| `masterpaskalform` | ported / GUI | non-GUI logic in `network`, `node`, `cli`; widgets and handlers in `cmd/nosogui` |
| `mpgui`, `formexplore`, `mplang`, `translation` | GUI | `cmd/nosogui` (see below) |
| `mpmn` | skipped | not used by `Noso.lpr` nor by any live unit; superseded by `nosomasternodes` |
| `indylaz`, `Interfaces`, `Forms`, `LCLTranslator`, `sysutils` | skipped | toolkit and runtime packages replaced by Go standard library and Fyne |
| `Deprecated/*` (`mpcripto`, `mplang`, `mpminer`, `mpmn`, `mptime`, `poolmanage`) | skipped | not referenced by any live unit (checked in `Noso.lpr` and all `uses` clauses) |
| `docs_site/`, `Packages/` | skipped | documentation website and bundled third party libraries (CryptoLib4Pascal, HashLib, SimpleBaseLib, Indy, dcpcrypt): replaced by Go code or standard library |

## `nosocrypto`

| Routine | Status | Go |
|---|---|---|
| `HashSha256String`, `HashMD160String` | ported | `SHA256String`, `RIPEMD160String` |
| `HashMD5String`, `HashMD5File` | changed | `IDHash`, `IDHashFile` (M-13); `MD5Hex` for the console |
| `IsValid58` | ported | `IsValid58` |
| `GetStringSigned`, `VerifySignedString` | changed | `SignCanonical`, `VerifyCanonical` (H-07, H-08, M-13) |
| `GetAddressFromPublicKey` | ported | `GetAddressFromPublicKey` |
| `NewGetAddressFromPublicKey` | ported | `NewGetAddressFromPublicKey` |
| `FutureGetAddressFromPublicKey` | skipped | unused experiment (only called by the `testhash` test command, which compares addresses with itself) |
| `GenerateNewAddress` | ported | `GenerateKeyPair` + `GetAddressFromPublicKey` |
| `IsValidHashAddress` | ported | `IsValidHashAddress` |
| `GetTransferHash`, `GetOrderHash` | ported | `GetTransferHash`, `GetOrderHash` |
| `GetCertificateChecksum`, `GetCertificate`, `CheckCertificate` | changed | `GetCertificate`, `CheckCertificate` (L-05) |
| `CheckHashDiff` | ported | `CheckHashDiff` (mining remnant, unused by the node) |
| `GetMultiSource` | ported | `GetMultiSource` |
| `B10ToB16`, `B10ToB58`, `B16ToB10`, `B16ToB36`, `B16ToB58`, `B16ToB58Lite1_60`, `B58ToB10`, `B58ToB16` | ported | `basen.go` |
| `ChecksumBase58`, `BMB58resumenNew`, `BMB58resumen`, `BMB58resumenInt` | ported | `basen.go` |
| `ClearLeadingCeros`, `BMAdicion`, `PonerCeros`, `BMMultiplicar`, `BMDividir`, `BMExponente`, `BMHexToDec`, `BM58ToDec`, `BMHexTo58`, `BMDecTo58`, `BMDecToHex` | ported | `basen.go` (`PonerCeros` is internal to the string multiplication, replaced by `math/big`) |
| `EncodeBaseN` (internal) | ported | `B16ToB36` / `encodeDigits` |

## `nosogeneral`

| Routine | Status | Go |
|---|---|---|
| `TStreamHelper.SetString/GetString` | ported | `storage/psos.go` (`uint16` length strings) |
| `Parameter`, `GetCommand`, `ProCommand` | ported | `codec` |
| `IsValidIP` | changed | `codec.IsValidIP` (L-02) |
| `GetSupply` | changed | `consensus.GetSupply` (L-06) |
| `Restar` | ported | `consensus.Restar` |
| `HashrateToShow` | skipped | mining display helper, unused by live code |
| `Int2Curr` | ported | `network.Int2Curr` |
| `RunExternalProgram` | skipped | used only by the removed updater/restart scripts |
| `GetCustFee`, `GetStackRequired`, `GetMNsPercentage`, `GetPoSPercentage`, `GetDevPercentage`, `GetMinimumFee`, `GetMaximunToSend` | ported | `consensus` |
| `OSVersion` | ported | `cli.osVersion` |
| `RequestLineToPeer`, `RequestToPeer` | ported | `network.Engine.RequestLine` |
| `SendApiRequest` | changed | `cli.FetchSeeds` (signed lists only, M-02) |
| `SaveTextToDisk`, `LoadTextFromDisk`, `TryCopyFile`, `TryDeleteFile` | ported | `storage` internals, `os` |
| `AppFileName` | skipped | used for restart scripts |
| `MixTxtFiles` | skipped | merges GUI log files into a report that was uploaded to the developers |
| `SendFileViaTCP` | skipped | uploaded that report |
| `UnzipFile` | changed | `node.StageBlocks` (C-02) |
| `CreateEmptyFile` | ported | `os.WriteFile` calls in `storage` |
| `GetStringFromOrder`, `ExtractMNsText` | ported | `types.StringFromOrder`, `codec.ExtractMNsText` |
| record types `TOrderData`, `TMultiOrder`, `TBlockOrdersArray` | ported / skipped | `types.Order`; `TMultiOrder` is unused |

## `nosotime`

| Routine | Status | Go |
|---|---|---|
| `GetNetworkTimestamp` | ported | `network.NetworkTimestamp` |
| `TimestampToDate` | ported | `cli.timestampToDate` |
| `GetTimeOffset`, `UpdateOffset` | changed | `Engine.UpdateTimeOffset` (median, M-03) |
| `UTCTime`, `UTCTimeStr` | ported | `Node.UTCTime`, `UTCTimeStr` |
| `TimeSinceStamp` | ported | `Node.TimeAgo` |
| `BlockAge`, `NextBlockTimeStamp`, `IsBlockOpen` | ported | `consensus` |

## `nosodebug`

| Routine | Status | Reason |
|---|---|---|
| `ToLog`, `CreateNewLog`, `GetLogLine`, `InitDeepDeb`, `ToDeepDeb`, `GetDeepDebLine` | ported (reduced) | `Node.Log` hook, `logx`; separate memo logs are the GUI's job |
| `BeginPerformance`, `EndPerformance`, `PerformanceToFile` | skipped | performance counters, no protocol effect |
| `AddNewOpenThread`, `UpdateOpenThread`, `CloseOpenThread`, `GetProcessCopy` | skipped | thread monitor table of the GUI "processes" tab (goroutines replace threads) |
| `AddFileProcess`, `CloseFileProcess`, `GetFileProcessCopy` | skipped | file-transfer monitor of the same tab |

## Storage units

| Routine | Status | Go |
|---|---|---|
| `nosounit`: `CreateProtocolOrder` | skipped | unused helper |
| `CreateNewSummaryFile`, `CreateSumaryIndex`, `GetIndexPosition`, `GetAddressBalanceIndexed`, `ResetBlockRecords`, `SummaryValidPay`, `SummaryPay`, `CreditTo`, `IsCustomizacionValid`, `UpdateSummaryChanges`, `GetAddressAlias`, `GetAddressLastOP`, `SetSummaryHash`, `MySumarioHash`, `SumIndexLength` | ported / changed | `storage.SummaryDB` |
| `ZipSumary`, `GetSummaryAsMemStream`, `GetZIPSummaryAsMemStream`, `SaveSummaryToFile`, `CreateSumaryBackup`, `RestoreSumaryBackup` | ported | `Node.ZipSummary`, `SummaryDB.Bytes/Replace/Backup/Restore` |
| `nosoheaders`: all 12 routines | ported | `storage.Headers` |
| `nosogvts`: `CreateGVTsFile`, `GetGVTsAsStream`, `SaveStreamAsGVTs`, `GetGVTsFileData`, `SaveGVTs`, `ChangeGVTOwner`, `GetGVTIndex`, `GetGVTLength`, `CountAvailableGVTs`, `GetGVTPrice` | ported | `storage.GVTs`, `GVTPrice` |
| `nosonosocfg`: all routines | ported | `storage.CFG` |
| `nosopsos`: file, locked-masternode, header and PSO routines | ported | `storage.PSOs` (`GetPSOHeadersFromFile` is replaced by `Load`) |
| `nosowallcon`: all routines | ported / changed | `storage.Wallet`, `OpenWalletEncrypted` |
| `nosoblock`: DB routines (`CreateDBFile` ... `GetOrderFromDB`) | ported; the index is always kept and filled with every block | `storage.BlocksDB` |
| `GetMyLastUpdatedBlock`, `GetBlockTrxs`, `LoadBlockDataHeader` | ported | `storage.Blocks` |
| `SaveStreamAsZipBlocks`, `GetBlocksAsStream` | changed | `node.ZipBlocks`, `StageBlocks` |

## Node and network units

| Routine (original) | Status | Go |
|---|---|---|
| `mpblock`: `CrearBloqueCero`, `BuildNewBlock`, `GetBlockReward`, `GuardarBloque`, `GetBlockPoSes`, `GetBlockMNs`, `UndoneLastBlock`, `RemoveBlocks`, `GEtNSLBlkOrdInfo` | ported / changed | `node/block.go`, `storage.Block`, `consensus` |
| `mpcoin`: `GetAddressAvailable`, `GetAddressPendingPays`, `GetAddressIncomingpays`, `VerifyIfPendingIsMine`, `AddressAlreadyCustomized`, `GVTAlreadyTransfered`, `AliasAlreadyExists`, `SendFundsFromAddress`, `CheckForMyPending`, `GetCurrentStatus`, `GetBlockHeaders`, `ValidRPCHost`, `PendingRawInfo` | ported / changed | `node`, `network`, `rpc`, `cli` (`GetFee` is inlined in `consensus.GetFee`) |
| `mpdisk`: `FileStructure`, `VerifyFiles`, `CreateADV`, `LoadADV`, `SaveUpdatedFiles`, `UpdateWalletFromSumario` (a no-op in the source), `RebuildSummary`, `AddBlockToSumary`, `CompleteSumary` | ported | `node.New`, `storage.Options`, `node/block.go` |
| `mpdisk`: `UnZipUpdateFromRepo`, `CreateLauncherFile`, `RestartNoso` | skipped | self-update and restart scripts (C-08) |
| `mpdisk`: `RestoreBlockChain`, `RestoreSumary` | ported | `cli` maintenance commands |
| `mpprotocol`: `GetOrderFromString`, `GetStringFromBlockHeader`, `ParseProtocolLines`, `PTC_SendLine`, `GetPingString`, `PTC_SendResumen`, `PTC_SendSumary`, `PTC_SendPSOS`, `PTC_SendGVTs`, `CreateZipBlockfile`, `PTC_SendBlocks`, `PTC_Custom`, `ValidateTrfr`, `IsAddressLocked`, `IsOrderIDAlreadyProcessed`, `PTC_Order`, `PTC_SendGVT`, `PTC_CFGData`, `PTC_SendUpdateHeaders`, `PTC_ProcessMNFileIncoming`, `PTC_HeadUpdate`, `INC_PTC_*`, `AddCriptoOp`, `DeleteCriptoOp` | ported / changed | `types`, `network/protocol.go`, `node/pool.go` (the crypto-operation queue is replaced by goroutines) |
| `mpprotocol`: `ZipHeaders`, `PTC_AdminMSG` update/restart branches | skipped | unused zip of the headers; remote update/restart (C-08) |
| `mpred`: slot and connection routines, `StartServer`, `StopServer`, `ForceServer`, `ConnectClient`, `LeerLineasDeClientes`, `VerifyConnectionStatus`, `SyncWithMainnet`, `GetOrderDetails`, `GetOrderSources`, `GetNodeStatusString`, `IsSafeIP`, `GetMiIP`, `NodeServerInfo`, `ClearReceivedOrdersIDs`, `SendOrderToNode` | ported / changed | `network` |
| `mpred`: `GetLastRelease`, `GetRepoFile`, `GetOS`, `GetLastVerZipFile` | skipped | update machinery (C-08) |
| `nosonetwork`: pending pool, protocol header/ping, slot table, bots, node list | ported / changed | `node/pool.go`, `network` |
| `nosonetwork`: `NodeServerEvents.OnExecute` (body is commented out in the source) | skipped | replaced by the real handlers of the main unit |
| `nosoconsensus`: `CalculateConsensus`, `GetConsensus`, `GetRandonNode`, `GetConHash`, `SetNodesArray`, `GetNodesArrayIndex/Count`, start/stop of the auto thread | ported / changed | `network/consensus.go` (`GetRandonNode` is unused) |
| `nosomasternodes`: all routines | ported / changed | `node/mn.go`, `storage/masternodes.go`, `network/run.go` |
| `mprpc`: all routines | ported / changed | `rpc` |
| `mpsyscheck` | ported | `cli` |

## Console commands (`mpparser.ParseCommandLine`)

Every command of the dispatch table exists, except these which were
removed: `update`, `getbeta`, `checkupdates`, `sendreport`, `testnet`
(security, C-08 and M-02). `clear`, `setport`, `showpending` and `clearpsos` keep their
original (no-op or "deprecated") behaviour `newpso` and `clearpsos` were removed: they changed the PSO file of one node only, and no block carries a PSO, so none can be created (`newpso` answers with that reason). `expkeys` prints the keys (the original copies them to the clipboard). `restart` works in nosod (in-process reopen); the GUI answers that it cannot restart. `TestEveryOriginalCommandHasAHandler`
checks the list.

## GUI (`cmd/nosogui`, Fyne, build tag `gui`)

The toolkit is Fyne 2.8.2. It needs a C compiler and OpenGL/X11 development
headers (it is not pure Go). Every row below says what was checked.
**Driven** = the real widgets were exercised in `cmd/nosogui/ui/ui_test.go`
with Fyne's test driver (`fyne.io/fyne/v2/test`, build tag `gui`): the test
taps, types and selects, then asserts on node state. **Rendered** = the screen
was drawn by Fyne's software renderer in that test and the PNG was looked at
(`NOSO_GUI_SHOTS=<dir> go test -tags gui ./cmd/nosogui/ui` writes them; with
no peers and an empty chain, so grids hold the default wallet, three funded
test addresses and nothing else). **Compiled only** = built, never drawn or
exercised. NOT done: the real OpenGL window of the binary was not started
in this review round, so window-system behaviour (native dialogs, menu bar,
clipboard, window close button) is unverified. The test driver also runs
`fyne.Do` inline, so the one-second refresh loop is not exercised.

| Original form / handler | Go | Verified |
|---|---|---|
| `FormInicio` (startup grid), `StartProgram`, `InicoTimerEjecutar` | `ui.showStartup`, `ui.startNode` | startup prompt compiled only; `startNode` driven (data directory, wallet, node) |
| Main form `TForm1`, menu (`MMImpWallet`, `MMExpWallet`, `MMRestart`, `MMQuit`) | `ui.buildMain`, File menu | rendered (all six tabs); File menu: Quit goes through `shutdown` (driven), import/export dialogs compiled only. Restart item removed |
| Status bar (`UpdateStatusBar`, `StaConLab`, rotor, server/RPC icons, clock) | status label in `refresh` | rendered; refresh loop compiled only |
| Info line (`Info`, `InfoTimer`) | `ui.info` | compiled only |
| `TabAddresses`: `DireccionesPanel` and draw cell, `BDefAddrOnClick`, `BCustomAddrOnClick`, `EditCustomKeyUp`, `BOkCustomClick`, `PanelCustomMouseLeave`, `BNewAddrOnClick`, `BCopyAddrClick`, `LabelBigBalance` | wallet tab | rendered; selection driven (`TestSendFromSelectedAddress`); customize, set default, copy, new address compiled only |
| Send panel: `SBSCPasteOnClick`, `SBSCMaxOnClick`, `EditSCDestChange`, `EditMontoOnKeyUp` (replaced by validation of the amount text), `EditSCMontChange`, `SCBitSendOnClick`, `SCBitConfOnClick`, `SCBitCancelOnClick`, `ResetSendFundsPanel` | wallet tab form | driven: select address, enter destination and amount, Send, Confirm, order built from the selected address (`TestSendFromSelectedAddress`); paste, max, cancel compiled only |
| `TabConsole`, `ConsoleLineKeyup` (Enter, F3, Esc), console and line popups (`ConsolePopUpClear/Copy`, `ConsoLinePopUp*`) | console tab (buttons replace popups) | rendered; typed command and Enter driven (`TestConsoleCommands`); F3/Esc, popups compiled only |
| `TabMonitor`: data panel (`InitGUI`, `DataPanelResize`), `SGConSeeds`/consensus, connections form `FormSlots` (`StaConLabDblClick`) | monitor tab: Data, Connections, Consensus | rendered (Data, Connections, Consensus); Consensus empty without peers |
| Debug logs (`MemoLog`, `MemoExceptLog`, `Button1Click`, `Button2Click`, `TUpdateLogs`) | Events and Exceptions sub tabs | rendered (empty) |
| Processes tab (`SG_OpenThreads`, `SG_FileProcs`, performance grid) | informational goroutine/memory page | rendered; thread and file tables intentionally not ported (no counterpart) |
| `TabNodes` / `GridNodes`, reported and verified masternodes | masternodes tab | rendered, empty list (no masternodes in the fixture) |
| `TabGVTs`, `GVTsGrid`, `PanelTransferGVT` | GVT tab | rendered; the 100 GVTs of a chain belong to its first proposer; transfer end to end in `network` tests (`sendgvt`), the dialog compiled only |
| Options: wallet (`CB_WO_HideEmptyChange`, `CB_WO_MultisendChange`, `CBKeepBlocksDBChange`, `CBRunNodeAloneChange`) | options, Wallet | rendered; hide-empty checkbox driven (`TestHideEmptyOption`) |
| Options: `CB_WO_AutoupdateChange`, `CBSendReportsChange` | removed | skipped on purpose (C-08, no reports are uploaded) |
| Options: node (`TabNodeOptionsShow`, `BSaveNodeOptionsClick`, `BTestNodeClick`, `CBAutoIPClick`) | options, Node | rendered; save and test compiled only |
| Options: RPC (`CB_AUTORPCChange`, `LE_Rpc_PortEditingDone`, `LE_Rpc_PassEditingDone`, `CB_RPCFilterChange`, `CB_BACKRPCaddressesChange`, `MemoRPCWhitelistEditingDone`, `MemobannedmethodsEditingDone`) | options, RPC (the password became two tokens) | rendered; the 'save new addresses' box is gone (it wrote plaintext key files, H-10); start/stop compiled only |
| Options: About (`BitBtnWebClick`, `BitBtnDonateClick`, `Tab_Options_AboutResize`) | options, About | rendered; links compiled only |
| `formexplore` (file chooser) | native Fyne file dialogs for import and export | export asks for a directory and writes through `expwallet` (never overwrites); dialogs compiled only |
| `mpgui` helpers (`ThisPercent`, resize handlers, `ProcessHint`, `UpdateMyGVTsList`, `OutText`, `CloseAllForms`) | Fyne layout, `ui.refresh` | layout code compiled only |
| `mplang`, `translation` (resource strings, `.po` files) | skipped | the GUI is English only; translating is a data task, not logic |
| `FormCloseQuery`, `CloseeAppSafely` | `ui.shutdown` | driven (`TestShutdownOnce`: options saved, servers stopped, closed marker written, once) |
| `TThreadDirective`, `TThreadKeepConnect` etc. | `network.Engine` goroutines | logic, tested in `network` |

No business logic lives in the GUI: balances, sending, customization, GVT
transfers, options and commands go through `node`, `network`, `cli` and
`rpc`.
