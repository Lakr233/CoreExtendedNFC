# CoreExtendedNFC — Agent Instructions

## What This Project Is

A Swift Package that provides NFC protocol-layer logic for iOS. CoreNFC handles RF transport; this library provides card identification, command construction, memory models, passport/eMRTD reading, and dump orchestration.

Zero external dependencies. Swift 6.2 strict concurrency. iOS 15+.

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
│   ├── PassportAPDU.swift          eMRTD APDU builders (ICAO 9303 Part 10)
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
│   └── Passport/          BAC, PACE, CA, AA, SM, DG parsers (13 files)
│
├── Crypto/             AES-CMAC, ISO 9797 MAC, key derivation, padding, hashing
├── Models/             CardType, CardInfo, MemoryDump, AccessBits, MRZ, Passport
└── Utilities/          Hex, byte, parity helpers
```

## Public API (CoreExtendedNFC.swift)

```swift
CoreExtendedNFC.scan()           → (CardInfo, NFCTagTransport, NFCSessionManager)
CoreExtendedNFC.scanAndDump()    → (CardInfo, MemoryDump)
CoreExtendedNFC.dumpCard()       → MemoryDump
CoreExtendedNFC.readPassport()   → PassportModel
```

## Build & Test

```bash
xcodebuild -project Example/CENFC.xcodeproj -scheme CENFC -destination 'generic/platform=iOS Simulator' build
# Run package builds/tests only in an iOS-capable toolchain; macOS compatibility is out of scope.
```

Tests use `MockTransport` to simulate NFC tag responses.

## Boundary Rules

| Layer      | CoreNFC import? |
| ---------- | --------------- |
| Transport/ | YES             |
| Protocol/  | **NO**          |
| Models/    | **NO**          |
| Cards/     | **NO**          |
| Crypto/    | **NO**          |
| Utilities/ | **NO**          |

**Only Transport/ and NFCSessionManager may import CoreNFC.** Everything else is pure logic.

## Coding Conventions

- **Swift 6.2** strict concurrency. All public types must be `Sendable`.
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
         → BAC key derivation (ICAO 9303 Part 11 Appendix D)
         → Secure Messaging (DO'87/DO'99/DO'8E, ISO 9797-1 MAC)
         → Read DG1 (MRZ), DG2 (face), DG14 (security info), DG15 (AA key), SOD
         → Passive Authentication (RFC 5652 CMS, hash verification)
         → Active Authentication (INTERNAL AUTHENTICATE, ICAO 9303 Part 11 §9.2)
```

PACE and Chip Authentication stubs exist but ECDH key agreement is not yet implemented.

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

## What NOT to Do

- **Never** attempt MIFARE Classic authentication (0x60/0x61) — iOS cannot handle Crypto1 parity bits. Classic is identification-only.
- **Never** import CoreNFC in Protocol/, Models/, Cards/, or Crypto/ files.
- **Never** block the main thread — all NFC ops are async.
- **Never** hardcode session timeout handling — let CoreNFC manage it, catch the error.
- **Never** add external crypto dependencies unless implementing DESFire auth or PACE ECDH.
