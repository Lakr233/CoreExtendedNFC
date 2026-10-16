# CoreExtendedNFC — Agent Instructions

## What This Project Is

A Swift Package that provides NFC protocol-layer logic for iOS. CoreNFC handles RF transport; this library provides card identification, command construction, memory models, passport/eMRTD reading, and dump orchestration.

One external dependency: `openssl-spm` (OpenSSL), imported only by the passport code (PACE, Active Authentication, SOD/CMS verification). Swift 6.2 strict concurrency. iOS 15+.

This project is iOS-only. Do not add `#if canImport(CoreNFC)` or macOS compatibility shims. Validation should target iOS builds only.

## Project Structure

```
Sources/CoreExtendedNFC/
├── Transport/          CoreNFC tag wrappers
│   ├── NFCTransport.swift          NFCTagTransport protocol
│   ├── NFCSessionManager.swift     Session lifecycle (async/await)
│   ├── MiFareTransport.swift       NFCMiFareTag adapter
│   ├── ISO7816Transport.swift      NFCISO7816Tag adapter
│   ├── FeliCaTransport.swift       NFCFeliCaTag adapter
│   └── ISO15693Transport.swift     NFCISO15693Tag adapter
│
├── Protocol/           Pure logic, ZERO CoreNFC imports
│   ├── ISO14443.swift              CRC_A/CRC_B (ISO 14443-3)
│   ├── CardIdentifier.swift        ATQA+SAK → CardType (NXP AN10833)
│   ├── APDUBuilder.swift           ISO 7816-4 APDU construction
│   ├── CommandAPDU+Passport.swift  eMRTD APDU builders (ICAO 9303 Part 10)
│   ├── ASN1Parser.swift            BER-TLV parser (ITU-T X.690)
│   └── NFCErrors.swift             NFCError enum
│
├── Cards/
│   ├── MiFareUltralight/  READ/WRITE/FAST_READ/GET_VERSION/PWD_AUTH
│   ├── NTAG/              READ_SIG/READ_CNT, variant detection
│   ├── DESFire/           Native wrapping, AF chaining, app/file ops
│   ├── FeliCa/            Type 3 NDEF, frame assembly
│   ├── ISO15693/          Block read/write, system info
│   ├── Type4/             NDEF via ISO 7816 SELECT/READ BINARY
│   ├── IndividualNumber/  Japanese My Number card APDU flows
│   ├── Transit/           Japan IC, Octopus, CEPAS, KS X 6924, T-Union
│   └── Passport/          BAC, PACE, CA, AA, SM; DG parsers in DataGroups/
│
├── Crypto/             AES-CMAC, ISO 9797 MAC, key derivation, padding, hashing
├── Concurrency/        LockedValue (lock-protected shared state)
├── Logger/             NFCLogger, NFCLogConfiguration, LogStore, payload redaction
├── Models/             CardType, CardInfo, MemoryDump, AccessBits, MRZ, Passport
├── Resources/          Localizable.xcstrings (en, zh-Hans)
└── Utilities/          Hex, byte, parity helpers
```

## Public API (CoreExtendedNFC*.swift)

```swift
// Session-owning flows; manager: accepts an NFCSessionManager subclass
CoreExtendedNFC.scan(pollingTargets:message:manager:)          → (CardInfo, any NFCTagTransport, NFCSessionManager)
CoreExtendedNFC.scanAndDump(pollingTargets:message:manager:)   → (CardInfo, MemoryDump)
CoreExtendedNFC.readPassport(mrzKey:dataGroups:performActiveAuth:trustAnchorsDER:message:manager:onProgress:) → PassportModel
CoreExtendedNFC.readMyNumberCard(items:cardInfoInputSupportPIN:message:manager:onProgress:)                  → MyNumberCardData

// Over a connected transport (no session handling)
CoreExtendedNFC.dumpCard(info:transport:)                      → MemoryDump
CoreExtendedNFC.readNDEF / writeNDEF / formatNDEF(info:transport:)
CoreExtendedNFC.readPassport(transport:mrzKey:dataGroups:performActiveAuth:trustAnchorsDER:onProgress:) → PassportModel
CoreExtendedNFC.readMyNumberCard(transport:items:cardInfoInputSupportPIN:onProgress:)                  → MyNumberCardData
CoreExtendedNFC.lookupMyNumberRemainingPINAttempts(transport:pinType:)                                 → Int
CoreExtendedNFC.readTransitBalance(info:transport:)            → TransitBalance

// Offline
PassportModel(rawDataGroups:cardAccessRaw:performPassiveAuthentication:trustAnchorsDER:dataGroupReadStatus:)
```

Family facades are named verb + family + noun: `readUltralightPages`, `writeUltralightPage`, `readNTAGSignature`, `getDESFireApplicationIDs`, `readISO15693Blocks(range: ClosedRange<Int>, ...)`, `authenticateISO15693`, `readType4CapabilityContainer`, and so on. The 1.x names (`readPages`, `writePage`, `getApplicationIDs`, `iso15693Authenticate`, `readType4CC`, ...) are deprecated forwarders; do not use them in new code. User-facing changes are recorded in `CHANGELOG.md`, and upgrade steps in `docs/guide/migrating-to-2.html`.

## Access Policy

The library is open by default: callers may subclass, override, overload and extend it.

- Transports, `NFCSessionManager`, `LogStore`, `SecureMessagingTransport` and every reader / command type are `open class ...: @unchecked Sendable` with immutable (`public let`) stored state. Main I/O entry points in the class body are `open`; members in extensions are `public` (Swift cannot override them). Static hooks on open classes are `open class func`.
- Every `open class` that is `@unchecked Sendable` carries the doc comment: "Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable."
- Value models (`CardInfo`, `MemoryDump`, `PassportModel`, `TransitBalance`, ...) stay structs with public members. Parsers, constants and helpers are `public`. Do not add `@frozen`.
- Kept sealed for stability or security; do not open these:
  - `SecureMessagingTransport`: keys, SSC, exchange gate, `protect` / `unprotect` / MAC / IV helpers stay private; `sendAPDU` is `public`, not `open`.
  - `NFCSessionManager`: scan state stays private; `scan(for:message:)`, `invalidate*`, `setAlertMessage` and the delegate callbacks are `public`, not `open`. Customization goes through `sessionDidBecomeActive`, `sessionDidInvalidate`, `invalidateAfterFailure`, `failureOutcome`, `invalidationError`, `pollingOptions` and `identifyTag`.
  - `LockedValue`, `AsyncExchangeGate`, `SessionTerminationMonitor` and `OpenSSLPACECurve` stay `public final` with private lock / pointer state. `OpenSSLPACECurve` is intentionally not `Sendable`: it owns a `BN_CTX` and is used inside a single PACE run.
  - OpenSSL `OpaquePointer` helpers in `ActiveAuthenticationVerifier` and `SODParser`, and `LogStore.performSync`, stay private.

## Build & Test

```bash
xcodebuild -project Example/CENFC.xcodeproj -scheme CENFC -destination 'generic/platform=iOS Simulator' build
# Run package builds/tests only in an iOS-capable toolchain; macOS compatibility is out of scope.
```

Tests use `MockTransport` to simulate NFC tag responses.

## Boundary Rules

| Layer        | CoreNFC import? |
| ------------ | --------------- |
| Transport/   | YES             |
| Protocol/    | **NO**          |
| Models/      | **NO**          |
| Cards/       | **NO**          |
| Crypto/      | **NO**          |
| Logger/      | **NO**          |
| Concurrency/ | **NO**          |
| Utilities/   | **NO**          |

**Only Transport/ and NFCSessionManager may import CoreNFC.** Everything else is pure logic.

## Coding Conventions

- **Swift 6.2** strict concurrency. All public types must be `Sendable` (the one exception is `OpenSSLPACECurve`; see Access Policy).
- **async throws** for all NFC operations. No completion handlers.
- File naming: PascalCase noun (`UltralightCommands.swift`). One primary type per file.
- Card code under `Cards/<Family>/`.
- Byte constants as hex literals: `0x30`, `0xA2`, `0x60`.
- Data construction: `Data([0x30, page])`.
- Errors: throw `NFCError` cases, never return optionals for failures.
- Tests: `<Module>Tests.swift`, Swift Testing framework (`import Testing`, `@Test`, `#expect`).

## DESFire Wrapping Pattern

```
[0x90, CMD, 0x00, 0x00, LEN, DATA..., 0x00]
```

AF chaining: keep sending `[0x90, 0xAF, 0x00, 0x00, 0x00]` until SW2 != 0xAF.

## Passport/eMRTD Protocol Stack

```
MRZ input → MRZKeyGenerator (ICAO 9303 Part 3, weights 7,3,1)
         → EF.CardAccess → PACE (ECDH Generic Mapping, NIST P-256/384/521, OpenSSL)
           or BAC key derivation (ICAO 9303 Part 11 Appendix D) as fallback
         → Secure Messaging (DO'87/DO'99/DO'8E, ISO 9797-1 MAC or AES-CMAC)
         → Read EF.COM + EF.SOD (index), DG1 (MRZ, mandatory), DG2 (face), DG14, DG15 (AA key), EAC DG3/DG4 last
         → Passive Authentication (RFC 5652 CMS, hash verification, DSC certification path validation to a CSCA in trustAnchorsDER)
         → Active Authentication (INTERNAL AUTHENTICATE, ICAO 9303 Part 11 §6.1);
           succeeded only with fully verified PA and a matching DG15 hash
```

PACE supports ECDH Generic Mapping on NIST curves only; other mappings fall back to BAC. Chip Authentication is parsed from DG14 but not performed (its ECDH key agreement is not implemented).

## Standards Referenced in Code

| Standard                | What it covers                            |
| ----------------------- | ----------------------------------------- |
| ICAO 9303 Parts 3/10/11 | MRZ, LDS, BAC, SM, AA, PA                 |
| BSI TR-03110 Part 3     | PACE, CA, TA OIDs                         |
| ISO/IEC 7816-4          | APDU structure                            |
| ISO/IEC 14443-3         | CRC_A/CRC_B, ATQA/SAK                     |
| ISO/IEC 9797-1          | MAC Algorithm 3, Padding Method 2         |
| ITU-T X.690             | BER/DER TLV encoding                      |
| RFC 4493                | AES-CMAC                                  |
| RFC 5652                | CMS SignedData (SOD)                      |
| NIST FIPS 197/180-4     | AES, SHA-1/256                            |
| NXP datasheets          | NTAG, Ultralight, DESFire, Classic, ICODE |

## Example App Conventions

The `Example/` Xcode project is a UIKit companion app. It has its own conventions on top of the library rules above.

### Auto Layout

Use **SnapKit** for all Auto Layout constraints. Do not use `NSLayoutConstraint.activate` or `translatesAutoresizingMaskIntoConstraints` — SnapKit handles both.

```swift
// ✅
view.addSubview(tableView)
tableView.snp.makeConstraints { make in
    make.edges.equalToSuperview()
}

// ❌
tableView.translatesAutoresizingMaskIntoConstraints = false
NSLayoutConstraint.activate([...])
```

### Feedback Patterns

- **Error / important feedback**: `UIAlertController` (.alert) — user must acknowledge.
- **Lightweight feedback** (copy, import, etc.): `SPIndicator` toast — non-intrusive.
- **User choice dialogs** (delete confirm, duplicates): `UIAlertController`.

### Empty States

List view controllers (Scanner, Dump, NDEF, Passport) use `EmptyStateView` for empty-list placeholders:

- Installed as a subview of the table view via `emptyState.install(on: tableView)`.
- Visibility toggled by checking the data store's `records.isEmpty`.
- Fades on scroll via `emptyState.updateAlpha(for: scrollView)` in `scrollViewDidScroll`.

### Dismiss Keyboard

All view controllers call `setupDismissKeyboardOnTap()` in `viewDidLoad()`.

### Localization

- Source language: `en`, with `zh-Hans` translations.
- Use `String(localized:)` for all user-facing text.
- After adding new strings, backfill `en` values — see memory notes for the script.

### Documentation Site

- The documentation site under `docs/` is part of release readiness.
- When a fix or feature changes public behavior, update the docs site alongside code and tests.
- Before considering release work complete, verify both tests and relevant docs site pages have been updated.

## What NOT to Do

- **Never** attempt MIFARE Classic authentication (0x60/0x61) — iOS cannot handle Crypto1 parity bits. Classic is identification-only.
- **Never** import CoreNFC in Protocol/, Models/, Cards/, or Crypto/ files.
- **Never** block the main thread — all NFC ops are async.
- **Never** hardcode session timeout handling — let CoreNFC manage it, catch the error.
- **Never** add external crypto dependencies unless implementing DESFire auth or PACE ECDH.
- **Never** use raw `NSLayoutConstraint` in the Example app — use SnapKit.
