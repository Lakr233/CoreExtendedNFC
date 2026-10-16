# Changelog

All notable changes to CoreExtendedNFC are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-16

2.0 is a major release because it breaks source and behaviour compatibility with 1.1.2. The Swift tools version (6.2), the iOS 15 deployment target and the async/await API style are unchanged. See the [migration guide](docs/guide/migrating-to-2.html) for before/after code.

### Highlights

- Typed errors: `NFCError` gains cases for conditions that were reported as message strings, is `Equatable`, and `error.isNFCCancellation` tells you when to stay silent.
- Safer writes: Ultralight / NTAG writes refuse lock, OTP and configuration pages unless you pass `allowIrreversible: true`; ISO 15693 locks need `permanentlyLock: true`.
- Stricter passport trust: Passive and Active Authentication only report `succeeded` when the Document Signer certificate (DSC) in EF.SOD has a validated certification path to a CSCA you supply in `trustAnchorsDER`.
- Open API: transports, `NFCSessionManager` and every reader / command type are `open` classes you can subclass, and the top-level flows accept an injected `manager:`.
- Consistent facade names (`readUltralightPages`, `getDESFireApplicationIDs`, `authenticateISO15693`, ...). The old names still work as deprecated forwarders.
- ISO 15693 tags with more than 256 blocks are read, written, dumped and NDEF-formatted with the extended commands.
- Singapore CEPAS balance and history reader.
- Fixes from four rounds of bug hunting across protocol parsing, session lifecycle, passport conformance, NDEF mapping and transit readers.

### Breaking changes

#### Errors

- `NFCError` has new cases: `userCanceled`, `systemBusy`, `sessionInvalidatedByCaller`, `scanInProgress`, `checksumMismatch`, `responseChainTooLong(maxFrames:)`, `applicationNotFound(aid:)`, `iso15693Error(code:)`, `pinVerificationFailed(remainingAttempts:)`, `pinRequired(MyNumberPINType)`, `irreversibleWriteRefused(page:)`, `tagNotNDEFFormatted`, `ndefMessageNotFound`, `ndefCapacityExceeded(required:capacity:)`, `invalidParameter(String)`, `malformedDump(String)`. Exhaustive `switch` statements over `NFCError` no longer compile; add the cases or a `default`.
- Errors that were reported differently in 1.1.2:
  - A user dismissing the NFC sheet is `.userCanceled`, not `.sessionInvalidated(String)`. Check `error.isNFCCancellation`.
  - The FeliCa Type 3 attribute-block checksum is `.checksumMismatch`, not `.crcMismatch`.
  - ISO 15693 error codes `0x12` / `0x14` and Type 4 UPDATE BINARY `6982` / `6985` are `.tagLocked`. Other ISO 15693 error codes are `.iso15693Error(code:)`.
  - A transit card that no reader recognizes is `.tagNotSupported`.
  - Conditions that used `unsupportedOperation` / `invalidResponse` strings (no NDEF, capacity, PIN, bad arguments, malformed dumps) now throw their typed case.

#### Passport / eMRTD

- The Passive Authentication stage is `succeeded` only for `PassiveAuthenticationStatus.fullyVerified` (the Document Signer certificate (DSC) has a validated certification path to a CSCA in `trustAnchorsDER`). A valid signature without a validated certification path is `fallback`.
- The Active Authentication stage is `succeeded` only when Passive Authentication is fully verified and DG15 matches its hash in EF.SOD. A valid signature over an unauthenticated DG15 is `fallback`, and the result status is the new `ActiveAuthenticationStatus.verifiedUnauthenticatedKey`. A DG15 hash mismatch is `failed`.
- An empty Passive Authentication result is not valid, and a data group that was read but is missing from EF.SOD fails verification.
- Only `NFCError.dataGroupNotAvailable` skips a data group. Secure-messaging and transport errors propagate. `readPassport` throws when DG1 was requested but could not be read, or when nothing could be read. Otherwise it returns a partial model with `PassportModel.dataGroupReadStatus`.
- Only data groups listed in EF.COM or EF.SOD are selected.
- `onProgress` messages are localized.
- **Data compatibility:** the raw values of `SecurityProtocol.taECDSASHA224` and `.taECDSASHA256` were swapped in 1.x and now match BSI TR-03110 (`0.4.0.127.0.7.2.2.2.2.2` is SHA-224, `...2.2.3` is SHA-256). `Codable` data stored by 1.x decodes to the other case for these two values. Re-parse stored DG14 / EF.CardAccess bytes instead of trusting saved enum values.

#### Ultralight / NTAG writes

- `UltralightCommands.writePage` / `compatibilityWrite` gain `memoryMap:` and `allowIrreversible:` parameters (both have defaults). Without `allowIrreversible: true` they throw `NFCError.irreversibleWriteRefused(page:)` for pages 0-2, for page 3 (OTP) unless the write changes no bit, and, with a memory map, for every page outside the user data area.
- The top-level page writes also refuse every page above 15 when no memory map is passed.
- WRITE and COMPATIBILITY_WRITE require the `0Ah` ACK; an empty answer is a failure.
- `UltralightDump.restore(dump:map:target:)` gains `target: CardInfo?` and validates every page (and the card type when a target is given) before writing.
- `UltralightCommands.probeUltralightCMemory()` is `async throws` and rethrows session loss.

#### ISO 15693

- `ISO15693SystemInfo.dsfid`, `afi` and `icReference` are `UInt8?` (`nil` when the tag does not report them).
- `configureAFI` / `configureDSFID` (on `ISO15693SecurityManager` and the facade) take `permanentlyLock:`. The `lock:` overloads are deprecated and their `lock:` argument has no default, so `configureAFI(x)` always calls the non-locking variant.
- Tags that do not report their memory size are rejected by dump and NDEF write (`unsupportedOperation`).
- Tags with more than 256 blocks are dumped with extended reads; a tag that rejects them is dumped up to block 255 and marked `partiallyReadable` instead of throwing.

#### NDEF

- Writing a message with no records erases the tag (Type 2 / Type 5: `03 00 FE`). Type 2 capacity is capped at CC2 × 8 bytes.
- Type 5 writes read and validate the CC first; an unformatted tag throws `tagNotNDEFFormatted`.
- A message that does not fit throws `ndefCapacityExceeded(required:capacity:)`. Records are encoded with `validatedData()` before anything is written.
- RFU URI prefix codes decode to no prefix. UTF-16 text records without a BOM are big-endian.

#### DESFire

- `DESFireFileType` gains `.transactionMAC` (exhaustive switches must handle it).
- EV2 session keys and IVs follow AN12196; hardware versions `0x12` / `0x22` / `0x42` are EV2 and `0x33` is EV3. The dump skips locked applications / files and Transaction MAC files.

#### FeliCa

- `FeliCaCommands.readPlainServices` is `async throws` (was `async`). Tag loss throws instead of returning an empty result.

#### Transit

- `TransitTransaction.amount` and `balanceAfter` are `Int?` (were `Int`). `nil` means no recognized amount / no balance exposed; do not show it as zero.
- `amount` is an unsigned magnitude for every reader; the direction comes from `type`.
- Tag loss and cancellation throw instead of returning zero balances or truncated history.
- KS X 6924 history comes from SFI 4 records. CEPAS timestamps count from 1995-01-01 00:00 Singapore time.

#### MemoryDump

- Flipper, Proxmark3 MFU and libnfc MFD exports throw when a page is not exactly 4 bytes.
- Imports throw on out-of-range or duplicate pages, more than 256 pages, or a Proxmark header whose page count does not match. Proxmark header detection changed: a file that also matches a plain page dump is read as plain unless the header is plausible.

#### Logging

- `NFCLogConfiguration.logger` is a lock-backed computed static property.
- Payload bytes, UIDs and block contents are hidden by default; set `NFCLogConfiguration.logPayloads = true` to log them. PIN, password and authentication exchanges are always redacted.
- Removed the app-template `Logger` statics: `Logger.app`, `.ui`, `.network`, `.model`, `.database`, `.syncEngine`, `.chatService` and `Logger.loggingSubsystem`. Create your own `Logger(subsystem:category:)`.
- Renamed `Logger.debugFile` / `infoFile` / `errorFile` to `nfcDebugFile` / `nfcInfoFile` / `nfcErrorFile` (no forwarders).

#### Session

- A second concurrent `scan` on the same `NFCSessionManager` throws `NFCError.scanInProgress`.
- Cancelling the calling task (while waiting for a tag or while connecting) invalidates the session and throws `CancellationError`.
- Ending a pending scan with `invalidate()` throws `NFCError.sessionInvalidatedByCaller`.
- A failure that races a user cancel is reported as `.userCanceled`.

#### API shape

- `NFCSessionManager`, `MiFareTransport`, `ISO7816Transport`, `FeliCaTransport`, `ISO15693Transport`, `SecureMessagingTransport` and `LogStore` are `open class` (were `public final class`).
- Reader and command types are `open class` (were `struct`): `UltralightCommands`, `UltralightDump`, `DESFireCommands`, `DESFireDump`, `FeliCaCommands`, `FeliCaType3Reader`, `ISO15693Reader`, `ISO15693SecurityManager`, `Type4Reader`, `Type4Tag`, `PassportReader`, `MyNumberCardReader`, `JapanICReader`, `OctopusReader`, `KSX6924Reader`, `TUnionReader`, `CEPASReader`. All stored state is immutable and the initializers are unchanged, so call sites compile as before; they are now reference types.
- Facade functions were renamed to verb + family + noun. The old names remain as deprecated forwarders (see Deprecated).
- `MyNumberCardReader.read(items:cardInfoInputSupportPIN:onProgress:)` is the `open` override point. `read(items:cardInfoInputSupportPIN:)` is `public`, not overridable, and forwards to it.
- `CommandAPDU.le` is a computed property derived from the new `expectedResponseLength`.
- Card identification changes: ATQA `0304` + SAK `20` is DESFire; other SAK `20` and SAK `28` / `38` are `.smartMX`; Ultralight C is detected by READ `2Bh`; system code `88B4` is split into FeliCa Lite / Lite-S; NTAG210 / NTAG212 are detected from GET_VERSION.
- My Number: a refused PIN or a blocked PIN throws `pinVerificationFailed(remainingAttempts:)`; the PIN is never sent when the retry counter is already 0.

### Added

- `Error.isNFCCancellation`, `NFCError.isUserCancellation`, `NFCError: Equatable, LocalizedError` with localized (en, zh-Hans) descriptions.
- `CoreExtendedNFC.scan(pollingTargets:message:manager:)` and `scanAndDump(pollingTargets:message:manager:)`.
- `CoreExtendedNFC.readPassport(...manager:onProgress:)` and `readPassport(transport:mrzKey:dataGroups:performActiveAuth:trustAnchorsDER:onProgress:)` for a transport you already hold.
- `CoreExtendedNFC.readMyNumberCard(items:cardInfoInputSupportPIN:message:manager:onProgress:)`, `readMyNumberCard(transport:items:cardInfoInputSupportPIN:onProgress:)` and `lookupMyNumberRemainingPINAttempts(transport:pinType:)`.
- `NFCSessionManager` subclass hooks: `sessionDidBecomeActive(_:)`, `sessionDidInvalidate(_:error:)`, `invalidateAfterFailure(_:)`, and the class functions `identifyTag(_:monitor:)`, `pollingOptions(from:)`, `invalidationError(from:)`, `failureOutcome(for:userCanceled:)`. Also `wasCanceledByUser`.
- `PassportModel(rawDataGroups:cardAccessRaw:performPassiveAuthentication:trustAnchorsDER:dataGroupReadStatus:)` builds a model offline with the reader's own parsers.
- `PassportModel.dataGroupReadStatus`, `reverifyPassiveAuthentication(trustAnchorsDER:)`, `reverifyingSecurity(trustAnchorsDER:)`; `ActiveAuthenticationResult.classified(by:)`; `PassportSecurityStageResult.passiveAuthentication(_:sodPresent:)` and `activeAuthentication(_:passiveAuthentication:)`.
- ISO 15693 extended commands: `ISO15693Reader.readBlock(at:)`, `writeBlock(at:data:)`, `readAllBlocks(info:)`; reads, dumps, NDEF writes and `formatNDEF` past block 255.
- ISO 15693 facade ranges as `ClosedRange<Int>` (bounds-checked).
- Singapore CEPAS reader (`CEPASReader`), included in `readTransitBalance`.
- `NFCLogConfiguration.logPayloads` and `NFCLogRedaction`.
- `CommandAPDU.expectedResponseLength` with extended Lc / Le, `APDUExchange.transmit` (6Cxx retry, bounded 61xx chaining), `ResponseAPDU.binaryData(for:)`, `ResponseAPDU.isApplicationNotFound`.
- `CardIdentifier.identify(atqaValue:sak:)` and `atqaValue(wireOrder:)`.
- Public memberwise initializers for `ISO15693SystemInfo` and `UltralightMemoryMap`.
- Parsers, constants, crypto helpers, NDEF mapping (`NDEFTagMapping`) and facade helpers are `public`.

### Changed

- Type 5 `formatNDEF` on a tag with more than 256 blocks covers the whole memory with extended commands (CC magic `E2h`). It falls back to blocks 0-255 (CC magic `E1h`) when the tag rejects them.
- Type 5 `readNDEF` reads only the CC and the blocks covering the MLEN area.
- Type 4 writes split the NLEN / ENLEN header by MLc, and T4T 3.0 extended NDEF files (ENLEN) are supported.
- `FeliCaCommands.ServiceReadResult` and `CardInfoRefiner.FeliCaLiteConstants` are nested under their owners and public (they were private / internal top-level types).
- `LockedValue`, `AsyncExchangeGate`, `SessionTerminationMonitor` and `OpenSSLPACECurve` stay `final`. `OpenSSLPACECurve` is intentionally not `Sendable`: it owns an OpenSSL `BN_CTX` and is used within a single PACE run.

### Deprecated

Facade functions (each forwards to the new name):

| Deprecated | Use instead |
| --- | --- |
| `readPages(startPage:transport:)` | `readUltralightPages(startPage:transport:)` |
| `writePage(_:data:memoryMap:allowIrreversible:transport:)` | `writeUltralightPage(_:data:memoryMap:allowIrreversible:transport:)` |
| `fastRead(from:to:transport:)` | `fastReadUltralightPages(from:to:transport:)` |
| `compatibilityWrite(_:data:memoryMap:allowIrreversible:transport:)` | `compatibilityWriteUltralightPage(_:data:memoryMap:allowIrreversible:transport:)` |
| `readSignature(transport:)` | `readNTAGSignature(transport:)` |
| `readCounter(counterID:transport:)` | `readNTAGCounter(counterID:transport:)` |
| `passwordAuth(password:transport:)` | `authenticateUltralightPassword(password:transport:)` |
| `readAuthConfig(configStartPage:transport:)` | `readUltralightAuthenticationConfiguration(configStartPage:transport:)` |
| `getApplicationIDs(transport:)` | `getDESFireApplicationIDs(transport:)` |
| `selectApplication(_:transport:)` | `selectDESFireApplication(_:transport:)` |
| `getFileIDs(transport:)` | `getDESFireFileIDs(transport:)` |
| `getFileSettings(_:transport:)` | `getDESFireFileSettings(_:transport:)` |
| `iso15693CustomCommand(code:parameters:transport:)` | `sendISO15693CustomCommand(code:parameters:transport:)` |
| `iso15693Challenge(cryptoSuiteIdentifier:message:transport:)` | `challengeISO15693(cryptoSuiteIdentifier:message:transport:)` |
| `iso15693Authenticate(cryptoSuiteIdentifier:message:transport:)` | `authenticateISO15693(cryptoSuiteIdentifier:message:transport:)` |
| `iso15693KeyUpdate(keyIdentifier:message:transport:)` | `updateISO15693Key(keyIdentifier:message:transport:)` |
| `readISO15693Blocks(range: NSRange, transport:)` | `readISO15693Blocks(range: ClosedRange<Int>, transport:)` |
| `getISO15693BlockSecurityStatus(range: NSRange, transport:)` | `getISO15693BlockSecurityStatus(range: ClosedRange<Int>, transport:)` |
| `configureISO15693AFI(_:lock:transport:)` | `configureISO15693AFI(_:permanentlyLock:transport:)` |
| `configureISO15693DSFID(_:lock:transport:)` | `configureISO15693DSFID(_:permanentlyLock:transport:)` |
| `readType4CC(transport:)` | `readType4CapabilityContainer(transport:)` |
| `readMyNumberCard(info:transport:items:cardInfoInputSupportPIN:)` | `readMyNumberCard(transport:items:cardInfoInputSupportPIN:onProgress:)` |
| `lookupMyNumberRemainingPINAttempts(info:transport:pinType:)` | `lookupMyNumberRemainingPINAttempts(transport:pinType:)` |

Types and members:

| Deprecated | Use instead |
| --- | --- |
| `typealias ActiveAuthStatus` | `ActiveAuthenticationStatus` |
| `typealias PassiveAuthStatus` | `PassiveAuthenticationStatus` |
| `typealias ActiveAuthPublicKey` | `ActiveAuthenticationPublicKey` |
| `Type4Tag` | `Type4Reader` (`readCC()` is `readCapabilityContainer()`) |
| `ISO15693SecurityManager.configureAFI(_:lock:)` | `configureAFI(_:permanentlyLock:)` |
| `ISO15693SecurityManager.configureDSFID(_:lock:)` | `configureDSFID(_:permanentlyLock:)` |
| `ISO15693Reader.readAllBlocks(transport:)` | `readAllBlocks(info:)` |
| `ISO15693Reader.writeBlock(_:data:transport:)` | `writeBlock(at:data:)` |

### Fixed

- **Protocol parsing:** ASN.1 lengths and tags are bounded and slice-safe; APDU encoding never traps; NDEF chunked records are reassembled, Smart Poster decoding is not recursive, and URI abbreviation picks the longest prefix; `Data(hexString:)` rejects signs.
- **Session lifecycle:** lock-protected scan state, stale-session callbacks ignored, every continuation resumed exactly once, CoreNFC reader errors mapped to `NFCError` in every transport, the session closed when refinement fails, and a released manager invalidates its session.
- **Passport / eMRTD (ICAO 9303):** PACE K_pi and authentication token, rejection of reflected PACE keys, mandatory DO'8E / DO'99, strict unpadding, odd-INS and extended-length Secure Messaging, serialized exchanges so the SSC cannot desynchronize, SM session poisoning after an unsafe exchange, CA session keys, the DSC certification path validated on the certificate CMS actually used, constant-time MAC / token comparisons, AA before EAC data groups, and per-file read caps.
- **NDEF mapping:** Type 2 CC check, Type 5 8-byte CC and MLEN bounds, CC access bits, Type 4 read/write loops terminate and NLEN is bounded.
- **Ultralight / NTAG:** NTAG210/212 maps, two-phase COMPATIBILITY_WRITE, FAST_READ guards, partial dumps of read-protected tags, and log redaction of password and key writes.
- **DESFire:** zero IV for EV2First part 2, empty record files, record-size overflow, bounded AF chaining.
- **FeliCa:** 3-byte block list elements, service attribute codes, Type 3 attribute validation, 16-service read chunks.
- **Transit:** Japan IC console / process tables and purchase times, KS X 6924 SFI 4 records and Snapper detection, T-Union top-up type, AID labels.
- **MemoryDump:** imports, exports and diffs never trap or truncate.
- **Logging:** UTF-8-safe `readTail`, no queue deadlock, race-free logger configuration, file protection on log files.
- **My Number:** the retry counter is checked before VERIFY, items are de-duplicated so VERIFY is sent once, and the individual number is no longer found by regex.

[2.0.0]: https://github.com/Lakr233/CoreExtendedNFC/compare/1.1.2...2.0.0

Earlier versions: see [GitHub releases](https://github.com/Lakr233/CoreExtendedNFC/releases).
