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
- PACE on Brainpool curves (brainpoolP224r1 to brainpoolP512r1) as well as NIST P-256/384/521, with the first supported PACEInfo picked from EF.CardAccess.
- Fixes from four rounds of bug hunting and a spec-verification round across protocol parsing, session lifecycle, passport conformance, DESFire, NDEF mapping and transit readers.

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
- Passive Authentication is stricter: EF.SOD must have eContentType `2.23.136.1.1.1` and a matching signed contentType attribute, an LDSSecurityObject version of 0 or 1, and exactly one SignerInfo; a DSC with a keyUsage extension must assert digitalSignature (`trustChainInvalid` otherwise). An unknown LDSSecurityObject hash algorithm is `unsupportedHashAlgorithm` (it used to fall back to the SignedData digest algorithm and report a hash mismatch).
- Active Authentication fails for RSA moduli under 1024 bits (`ActiveAuthenticationVerifier.minimumRSAModulusBits`), RSA signatures that are not exactly the modulus length, and ECDSA signatures whose `r` / `s` are not exactly the curve order length.
- `PACEHandler.performPACE` throws `unsupportedOperation` for an unknown protocol OID (was `secureMessagingError`) and checks every parameter before sending any APDU. MSE:Set AT now carries tag `84` (domain parameter ID).
- `SecurityInfos.paceInfos` no longer contains PACEDomainParameterInfo entries (10-arc OID with an AlgorithmIdentifier); they are in the new `paceDomainParameterInfos`.
- `SecureMessagingTransport` accepts an AES SSC of 16 bytes (block size) or 8 bytes (zero-extended). Any other SSC length makes every exchange throw `invalidParameter` without sending anything.
- `MRZData` reassembles TD1 / TD2 document numbers longer than nine characters: `documentNumber` includes the overflow from the optional data field, and `optionalData1` no longer starts with the overflow and its check digit.
- **Data compatibility:** the raw values of `SecurityProtocol.taECDSASHA224` and `.taECDSASHA256` were swapped in 1.x and now match BSI TR-03110 (`0.4.0.127.0.7.2.2.2.2.2` is SHA-224, `...2.2.3` is SHA-256). `Codable` data stored by 1.x decodes to the other case for these two values. Re-parse stored DG14 / EF.CardAccess bytes instead of trusting saved enum values.
- Once DG15 is known to exist, the Active Authentication stage is `failed` unless the chip returns a valid signature. This covers a chip that refuses INTERNAL AUTHENTICATE with a plain status word or drops Secure Messaging there (it was `skipped`), and a DG15 that EF.SOD or EF.COM lists but that the chip does not return (it was `notAdvertised`). `activeAuthResult` is then `.commandFailed`. `skipped` now means only that you disabled AA, and `notAdvertised` that nothing lists DG15. `PassportReader.activeAuthenticationStage(...)` gains `dg15Evidence:` (default `nil`), and there is a new `PassportReader.dg15Evidence(rawDataGroups:sod:com:)`.
- The PACE stage is `failed` (possible PACE-to-BAC downgrade) when DG14 was read and lists a PACEInfo this library supports, but PACE did not complete. This covers EF.CardAccess missing, stripped or unsupported, and PACE failing before the BAC fallback (ICAO 9303-11 §9.2.11: DG14 repeats the SecurityInfos of the unprotected EF.CardAccess). BAC still runs and the data is returned. DG14 PACEInfos the library does not support change nothing. See the new `PassportReader.paceStage(_:paceCompleted:dg14SecurityInfos:passiveAuthResult:)`.
- `PACEHandler.performPACE` throws `secureMessagingError` before the mapping step when the chip's encrypted nonce is empty or not a whole number of cipher blocks (16 bytes for AES, 8 for 3DES; ICAO 9303-11 §4.4.3.3), and when the decrypted nonce is 0 modulo the curve order. The reader falls back to BAC, as it does for any PACE failure that does not end the session.
- `DG14Parser.decodeInteger(_:)` returns `Int?`: `nil` for an empty, negative or wider-than-`Int` INTEGER, which used to wrap silently. A PACEInfo, ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo, ActiveAuthenticationInfo or TerminalAuthenticationInfo with such an INTEGER is dropped, and so is an EF.SOD hash entry with such a data group number.
- `DG2Parser.maxSearchDepth` is 8 (was 32).

#### Ultralight / NTAG writes

- `UltralightCommands.writePage` / `compatibilityWrite` gain `memoryMap:` and `allowIrreversible:` parameters (both have defaults). Without `allowIrreversible: true` they throw `NFCError.irreversibleWriteRefused(page:)` for pages 0-2, for page 3 (OTP) unless the write changes no bit, and, with a memory map, for every page outside the user data area.
- The top-level page writes also refuse every page above 15 when no memory map is passed.
- WRITE and COMPATIBILITY_WRITE require the `0Ah` ACK; an empty answer is a failure.
- `UltralightDump.restore(dump:map:target:)` gains `target: CardInfo?` and validates every page (and the card type when a target is given) before writing.
- `UltralightCommands.probeUltralightCMemory()` is `async throws` and rethrows session loss.
- `UltralightCAccessConfiguration.requiresAuthenticationForReads` is now `true` when AUTH1 bit 0 is `0` (it was inverted), and an AUTH0 of `30h` or higher means no protection (`firstProtectedPage == nil`), not only exactly `30h`.
- GET_VERSION identification: NTAG I2C (product subtype `05h`) is `.mifareUltralight`; the 1k variant was reported as `.ntag216`, and the undocumented Ultralight storage code `06h` is no longer MF0UL11.
- GET_VERSION identification also requires the major version of the matching datasheet (`01h`; NTAG210u `02h`, NTAG213 TT `03h`): Ultralight Nano (`02h`/`03h`) and NTAG 223 DNA (`04h`) were mapped to MF0UL11 / NTAG213 and are now `.mifareUltralight` (proxmark3 `cmdhfmfu.c` version table).

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
- Reading an erased Type 3, Type 4 or Type 5 tag (empty NDEF message) throws `ndefMessageNotFound`, as Type 2 already did (was a parse error).
- On Type 2, `ndefCapacityExceeded(required:)` no longer counts the Terminator TLV, and a message that fills the data area exactly is accepted and written without one.
- Type 5 tags whose CC requires the special frame format (CC byte 3 b4) are refused with `unsupportedOperation`.
- Parsing is strict (NDEF 1.0 §3.2.6, Android `NdefMessage`): bytes after the record carrying ME, TNF Empty with a type / ID / payload, and TNF Unknown or Unchanged with a type throw `invalidResponse`. The reserved TNF `07h` is read like Unknown. `validatedData()` (and so `writeNDEF`) also refuses those records and any `.unchanged` / `.reserved` record with `invalidParameter`.
- Absolute-URI records (TNF `03h`) decode the URI from the TYPE field (was the payload); a Smart Poster without a `U` record takes its URI from an absolute-URI child.
- Type 2 reads skip the lock and reserved bytes declared by Lock Control / Memory Control TLVs (T2T 1.0 §2.3.4 / §2.3.5). Type 2 writes keep NULL and control TLVs at the start of the data area (so a preserved control TLV costs its bytes of capacity), stop before declared reserved bytes, and may read pages 7-10 once.
- `NDEFTagMapping.encodeNDEFTLV(_:)` now `throws`: a message longer than `FFFEh` bytes (the largest 3-byte TLV length; `FFFFh` is reserved) throws `ndefCapacityExceeded` instead of encoding a truncated length. Type 5 writes and `buildType5Blocks` cap their capacity there.
- Type 5 reads check the CC like writes do: a major version above 1 throws `tagNotNDEFFormatted` and a CC denying read access (CC1 b3-b2 ≠ `00b`) throws `tagLocked`; `extractType5Message` / `type5FormattedCCLength` return `nil` for them. New `NDEFTagMapping.type5ReadableCCLength(leadingBytes:)`.
- `buildType5Blocks` (and so `formatNDEF`) puts the NDEF TLV right after the CC (byte 4 or 8) for every block size; with 8-byte blocks and a 4-byte CC it used to start at byte 8.
- Type 2 writes keep leading Lock / Memory Control TLVs only when they are well formed (length 3) and followed by an NDEF or Terminator TLV (or only by NULL TLVs through page 10); other leading bytes are overwritten from page 4 instead of being kept or refusing the write.

#### DESFire

- `DESFireFileType` gains `.transactionMAC` (exhaustive switches must handle it).
- EV2 session keys and IVs follow AN12196; hardware versions `0x12` / `0x22` / `0x42` are EV2 and `0x33` is EV3. The dump skips locked applications / files and Transaction MAC files.
- `pcdCapabilities` (AuthenticateEV2First and the EV2 read helpers / facades) defaults to empty instead of six zero bytes and accepts 0 to 6 bytes. 1.1.2 required six bytes but always sent Part 1 as `KeyNo ‖ 00`; the empty default keeps that wire format. A non-empty value is now actually sent as `LenCap ‖ PCDcap2`, so an explicit six-zero-byte argument, ignored in 1.1.2, now sends `LenCap = 06` and six bytes; drop it. The EV2First Part 2 answer must be exactly 32 bytes.
- The AuthenticateISO read helpers (`readDataAuthenticatedISO`, `readRecordsAuthenticatedISO`, `getValueAuthenticatedISO`) strip the 8-byte CMAC the card appends, so they return 8 bytes less than before. The MAC is not verified.
- Hardware major version `0x43` is EV3.

#### FeliCa

- `FeliCaCommands.readPlainServices` is `async throws` (was `async`). Tag loss throws instead of returning an empty result.
- `writeFeliCaBlocks` writes one block per Write Without Encryption by default (was 4), because FeliCa Lite / Lite-S accept only one. Pass `maxBlocksPerWrite:` for cards that accept more.

#### Transit

- `TransitTransaction.amount` and `balanceAfter` are `Int?` (were `Int`). `nil` means no recognized amount / no balance exposed; do not show it as zero.
- `amount` is an unsigned magnitude for every reader; the direction comes from `type`.
- Tag loss and cancellation throw instead of returning zero balances or truncated history.
- KS X 6924 history comes from SFI 4 records. CEPAS timestamps count from 1995-01-01 00:00 Singapore time.
- Japan IC: ticket-machine and fare-adjustment records (console types `03`, `07`, `08`, `12`-`15`) have `exitStation == nil`; bus records (console type `05`) have no stations and put the line and stop codes in `metadata["busLineCode"]` / `metadata["busStopCode"]`.
- CEPAS: type `76` (bus refund) is a `.topup` and `04` (service charge) a `.purchase`, both with an amount (were `.unknown` without one).
- Japan IC: history slots whose date field is zero (unused slots such as `00 00 00 80 …`) are dropped, as Metrodroid does; records with an out-of-range date or purchase time are kept with `date == nil`; process `07h` (new issue, initial deposit) is a `.topup`.

#### MemoryDump

- Flipper, Proxmark3 MFU and libnfc MFD exports throw when a page is not exactly 4 bytes.
- Imports throw on out-of-range or duplicate pages, more than 256 pages, or a Proxmark header whose page count does not match. Proxmark header detection changed: a file that also matches a plain page dump is read as plain unless the header's version field is a GET_VERSION response or all zero.

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
- Card identification changes: ATQA `0304` + SAK `20` is DESFire; other SAK `20` (including MIFARE Plus ATQAs `0002` / `0004` / `0042` / `0044`, previously `.mifarePlusSL3_2K` / `_4K`) and SAK `28` / `38` are `.smartMX`; Ultralight C is detected by READ `2Bh`; system code `88B4` is split into FeliCa Lite / Lite-S; NTAG210 / NTAG212 are detected from GET_VERSION.
- My Number: a refused PIN or a blocked PIN throws `pinVerificationFailed(remainingAttempts:)`; the PIN is never sent when the retry counter is already 0.
- `ISO14443.parseATS` accepts an ATS that still starts with TL and returns empty fields when T0 b8 is set; `ATSInfo.maxFrameSize` maps FSCI 9-C to 512-4096 bytes (was 256).

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
- PACE on the Brainpool curves brainpoolP224r1, P256r1, P320r1, P384r1 and P512r1 (parameter IDs 11, 13, 14, 16, 17), alongside NIST P-256/384/521; `DomainParameterID.isBrainpoolCurve` and `isSupportedForPACE`.
- `PACEHandler.selectPACEInfo(from:)`, `isSupported(_:)` and `unsupportedReason(for:)`; `performPACE(...mappingPrivateKey:ephemeralPrivateKey:)` to replay test vectors such as ICAO 9303-11 Appendix G.1; `OpenSSLPACECurve.isValidPrivateScalar(_:)`.
- `PACEDomainParameterInfo` and `SecurityInfos.paceDomainParameterInfos`. `SecurityInfos` saved before these fields existed still decode.
- `ActiveAuthenticationVerifier.minimumRSAModulusBits`, `SODParser.ldsSecurityObjectOID` and `SODParser.validateLDSSecurityObjectVersion(_:)`.
- T4T mapping 1.0 support: `Type4Reader` falls back to the NDEF application `D2760000850100` (selecting files with P2 = `00h`); `Type4Constants.ndefAIDVersion1`, `Type4Reader.selectedApplicationAID`.
- `NDEFTagMapping.lengthLastWriteOrder(_:blockSize:tlvOffset:)` and `type5SpecialFrameFlag`; `UltralightCAccessConfiguration.firstProtectedPage(fromAUTH0:)`; `writeFeliCaBlocks(...maxBlocksPerWrite:...)`.
- Reference documents: vendored RFC 4493, RFC 5280, RFC 5652, NIST FIPS 197, FIPS 180-4 and SP 800-38B in `docs/references/` (licences in its README), and `docs/research/references.html` linking the ICAO, BSI, ISO/IEC, NFC Forum, NXP and Sony specifications and open-source cross-references.

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
- **Spec test vectors (self-check round 2):** executable tests for FIPS 197 / SP 800-38B / FIPS 180-4 examples, ICAO 9303-11 Appendices D, F, G and I plus Parts 3-6 and 10 specimens, proxmark3 DESFire / Ultralight vectors, AN10833 and MF1S50 access conditions, ndeflib / nfcpy / Android CTS NDEF vectors, and Metrodroid / FareBot transit dumps (`Tests/CoreExtendedNFCTests/Vectors/`).
- **Logging:** UTF-8-safe `readTail`, no queue deadlock, race-free logger configuration, file protection on log files.
- **My Number:** the retry counter is checked before VERIFY, items are de-duplicated so VERIFY is sent once, and the individual number is no longer found by regex.
- **PACE (spec verification):** the first supported PACEInfo is used instead of always the first (ICAO 9303-11 §4.4.4.1); MSE:Set AT sends the domain parameter ID in tag `84` (§4.4.4.1); PACEDomainParameterInfo is no longer parsed as PACEInfo (§9.2); unsupported parameters fall back to BAC before any PACE APDU.
- **Secure Messaging:** extended outer Le `0000` whenever the protected command is extended (ICAO 9303-11 §9.8, Figure 5); 16-byte AES SSC (§9.8.2); verified against the Appendix D.4 READ BINARY vector.
- **Passive Authentication:** eContentType and contentType attribute checked (RFC 5652 §11.1, ICAO 9303-10 §4.6.2); LDSSecurityObject version and PrintableString LDSVersionInfo (ICAO 9303-10 §4.6.2.2); DSC keyUsage digitalSignature (ICAO 9303-12). Documented limits: no CRL checks, CSCA link certificates must be supplied in `trustAnchorsDER` with their CSCA, exactly one SignerInfo.
- **Active Authentication:** RSA modulus and signature length checks (ICAO 9303-11 §6.1, ISO/IEC 9796-2), ECDSA `r ‖ s` length (BSI TR-03111 §5.2.1); `verify` documents that its result must go through `classified(by:)`.
- **MRZ:** TD1 / TD2 document numbers longer than nine characters (ICAO 9303-5 / -6 §4.2.2, Note j).
- **Passport (adversarial review round 3):** PACE no longer completes with a chip that sends an empty encrypted nonce or one that decrypts to 0 mod n. Such a nonce maps the generator to H, so the session keys did not depend on the password. A clone that refuses INTERNAL AUTHENTICATE or hides a listed DG15 no longer gets a `skipped` / `notAdvertised` AA stage. A PACE-to-BAC downgrade is detected from DG14. DG2 parsing walks TLV levels as slices, so deep nesting no longer copies a multi-megabyte payload at every level. `ASN1Parser.findTag` copies only the node it finds. There is a new `ASN1Parser.parseTLVHeaders(_:)` / `TLVHeader` for parsing without copies. DG14 INTEGERs no longer wrap.
- **API safety (adversarial review round 3):** an Ultralight C whose GET_VERSION NAK reaches the library as `tagConnectionLost` (how CoreNFC reports a NAKed optional command) is now probed with READ `2Bh` and identified, instead of staying `.mifareUltralight`; user cancel, session invalidation, timeouts and task cancellation still propagate (`CardInfoRefiner.isGetVersionNAK(_:)`). Public helpers no longer trap on caller input: `UltralightMemoryMap.isUserDataPage(_:)` is `false` for an empty range, `userDataByteCount` is computed in `Int` (0 for an empty range), the new `isValid` / `validate()` let `writePage` / `compatibilityWrite` / `UltralightDump.restore` refuse a malformed map with `invalidParameter`, `DESFireCommands.deriveISOSessionKey(key:rndA:rndB:)` throws `invalidParameter` for a key that is not 16 bytes or an RndA / RndB shorter than 8 bytes, and `readAuthConfig(configStartPage:)` checks the READ length. The `rndA:` / `randomA:` overloads are documented as test and trace seams. Log redaction also covers DESFire ChangeKeyEV2 (`C6h`), Ultralight AES key pages `30h`-`37h` (MF0AES(H)20 §8.6.3) and FeliCa Write Without Encryption to the Lite / Lite-S CK block `87h` (FeliCa Lite-S User's Manual §3.1.11).
- **DESFire:** AuthenticateISO session key for single-DES keys, including the all-zero factory key (proxmark3 `desfirecore.c`); CMAC stripped from plain responses after AuthenticateISO (proxmark3 `DesfireSecureChannelDecodeEV1`); EV2First sends PCDcap2 and requires a 32-byte Part 2 (AN12343 §10.1); GetVersion `0x43` = EV3 (proxmark3 `cmdhfmfdes.c`); `AESCMAC` accepts `Data` slices. Unsupported features are documented: AuthenticateAES, AuthenticateEV2NonFirst, CMAC secure messaging, command counter, TMAC.
- **NDEF (spec verification):** Type 2 and Type 5 write the TLV length as zero first and the real length last (NFC Forum T2T §6.4.3, T5T §7.5.1); erased Type 3 / 4 / 5 tags read as `ndefMessageNotFound`; T4T mapping 1.0 (nfcpy `tt4.py`); Type 5 special-frame CC refused (T5T §4.3.1); Type 2 exact-fill without terminator (T2T §2.3).
- **Identification:** SAK `20` with a MIFARE Plus ATQA is `.smartMX` (AN10833 §2.1); FSCI 9-C (ISO/IEC 14443-4:2016); ATS with TL, T0 b8 (ISO/IEC 14443-4 §5.2); NTAG I2C not taken for NTAG216 and storage code `06h` removed (NXP GET_VERSION tables); Ultralight C AUTH1 bit 0 and AUTH0 ≥ `30h` (MF0ICU2 §7.5.8, Table 12).
- **FeliCa:** one block per write by default (FeliCa Lite-S User's Manual, Write Without Encryption); failure logs print Status Flag 1 and 2 in hex; purse service attribute comments.
- **Transit (spec verification):** CEPAS bus refund `76` and service charge `04` amounts (Metrodroid `CEPASTransaction`); Japan IC ticket-machine and bus records (Metrodroid `SuicaTrip`); the Octopus offset documents that sources disagree (350 vs 500 after 2017-10-01) and how to override it with `OctopusReader(transport:balanceOffset:)`.
- **NDEF (adversarial review round 3):** a Type 2 / Type 5 write interrupted while finalising a 3-byte TLV length that spans two blocks no longer leaves a wrong non-zero length: the block holding the first length byte is written last. Type 5 formats with block sizes other than 4 or 8 read back. `extractTLVNDEF`, `parseTLVLength`, `type2WriteLayout`, `buildType2Area` and the Type 5 CC helpers accept `Data` slices. Type 4 writes document that the length update is not atomic when MLc is smaller than the NLEN / ENLEN field.
- **Transit / MemoryDump (adversarial review round 3):** `MemoryDump.importProxmark3MFU`, `CEPASReader.transaction(_:recordNumber:)`, `CEPASReader.readBalanceAndHistory(purse:)` and `TUnionReader.parseFileInfo(_:source:)` accept `Data` slices; a CEPAS record shorter than 16 bytes is an `.unknown` transaction and a T-Union file 15 shorter than 28 bytes gives `source == "unavailable"` instead of trapping. Proxmark3 MFU exports of 2, 6, 27, 31, 34, 121 or 217 pages, whose size equals a plain dump, import back as written (were read as plain pages or rejected). `TUnionReader.parseBCDDateTime` rejects non-BCD nibbles. Japan IC history keeps records whose date field is non-zero but out of range (Metrodroid `SuicaUtil.extractDate`); they were dropped.
- **Example app:** the MIFARE Classic access-bits decoder follows NXP MF1S50 Tables 7 and 8 (5 of 8 data-block and 6 of 8 sector-trailer conditions were wrong).

[2.0.0]: https://github.com/Lakr233/CoreExtendedNFC/compare/1.1.2...2.0.0

Earlier versions: see [GitHub releases](https://github.com/Lakr233/CoreExtendedNFC/releases).
