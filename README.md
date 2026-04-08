# CoreExtendedNFC

NFC protocol logic for iOS, built on top of CoreNFC.

Identify cards, read/write memory, dump tags, read eMRTD passports — async/await, zero external dependencies.

[![App Store Icon](./Example/Download_on_the_App_Store_Badge_US-UK_RGB_blk_092917.svg)](https://apps.apple.com/app/cenfc/id6760399948)

![CENFC App](./Example/Apptisan_CENFC.jpeg)

## Why This Exists

CoreNFC gives you the transport layer: session management, tag discovery, NDEF support, and raw tag-specific commands such as ISO 7816 APDUs, MiFare commands, FeliCa commands, and ISO 15693 block/custom commands.

What it does not provide is a built-in high-level protocol library. It doesn't know what an Ultralight page layout looks like, how to chain DESFire Additional Frames, how to negotiate BAC with a passport chip, or how to export a dump in Flipper or Proxmark3 formats.

This library does.

**What it covers:**

- **Card identification** — Decode ATQA + SAK bytes into 25+ card types (Ultralight, NTAG, DESFire, Classic, etc.)
- **Memory operations** — Read, write, and dump tag memory across Ultralight, NTAG, DESFire, FeliCa, ISO 15693, and Type 4 NDEF tags
- **DESFire application layer** — Enumerate apps and files, handle Additional Frame chaining, authenticated reads (ISO & EV2)
- **Passport / eMRTD reading** — BAC key exchange, Secure Messaging, data group parsing (MRZ, face photo), Passive & Active Authentication
- **My Number card (Japan)** — JPKI token read, individual-number read with card-info-input-support PIN, PIN-attempt lookup
- **Crypto primitives** — CRC_A/CRC_B, AES-CMAC, 3DES, ISO 9797-1 MAC, key derivation — all built-in, no external dependencies
- **Dump export** — Hex, JSON, Flipper NFC, and Proxmark3 formats
- **Testability** — `MockTransport` lets you unit-test all card logic without NFC hardware

**CoreNFC vs CoreExtendedNFC:**

|                                   |          CoreNFC           | CoreExtendedNFC |
| --------------------------------- | :------------------------: | :-------------: |
| Tag discovery & session           |            yes             |       yes       |
| Raw APDU send/receive             |            yes             |       yes       |
| Card identification               |          partial           |       yes       |
| Memory read/write/dump            |          partial           |       yes       |
| DESFire app/file operations       | no built-in high-level API |       yes       |
| NDEF read/write (Type 3 & 4)      |            yes             |       yes       |
| Passport reading & authentication |   possible, not built-in   |       yes       |
| Crypto (AES-CMAC, 3DES, MAC)      |        no built-in         |       yes       |
| Export (Flipper, Proxmark3, JSON) |        no built-in         |       yes       |
| Mock transport for testing        |        no built-in         |       yes       |

`partial` means CoreNFC exposes low-level or tag-specific primitives, but not a unified high-level abstraction for identification, dump orchestration, or family-specific memory models.

## Supported Cards

| Family                  | Identify | Read | Write | Dump |
| ----------------------- | :------: | :--: | :---: | :--: |
| MIFARE Ultralight / EV1 |   yes    | yes  |  yes  | yes  |
| NTAG 213 / 215 / 216    |   yes    | yes  |  yes  | yes  |
| MIFARE DESFire EV1–3    |   yes    | yes  |  yes  | yes  |
| FeliCa (Type 3 NDEF)    |   yes    | yes  |  yes  |      |
| ISO 15693 (ICODE, ST25) |   yes    | yes  |  yes  | yes  |
| Type 4 NDEF (ISO 7816)  |   yes    | yes  |  yes  |      |
| eMRTD / ePassport       |   yes    | yes  |       |      |
| My Number card (Japan)  |   yes    | yes  |       |      |
| MIFARE Classic 1K/4K    |   yes    |      |       |      |

> DESFire write is limited to free-access files. Classic is ID-only — iOS hardware can't do Crypto1.

Real hardware coverage is tracked in [Tested Cards](docs/Tested-Cards.md).

## Quick Start

```swift
import CoreExtendedNFC

// Scan and identify
let (card, transport, session) = try await CoreExtendedNFC.scan()
print(card.type.description, card.uid.hexString)
session.invalidate(message: "Done")

// Scan and dump
let (info, dump) = try await CoreExtendedNFC.scanAndDump()
print(dump.exportHex())

// Read a passport
let passport = try await CoreExtendedNFC.readPassport(
    mrzKey: "L898902C<3640812512041598",
    dataGroups: [.dg1, .dg2]
)
print(passport.mrz?.surname ?? "?")
```

## Card Operations

**Ultralight / NTAG**

```swift
let cmd = UltralightCommands(transport: transport)

let version = try await cmd.getVersion()
let pages   = try await cmd.readPages(startPage: 4)
try await cmd.writePage(4, data: Data([0x01, 0x02, 0x03, 0x04]))
let bulk    = try await cmd.fastRead(from: 4, to: 39)
```

**DESFire**

```swift
let desfire = DESFireCommands(transport: transport)

let version = try await desfire.getVersion()
let aids    = try await desfire.getApplicationIDs()
try await desfire.selectApplication(aids[0])
let files   = try await desfire.getFileIDs()
let data    = try await desfire.readData(fileID: files[0])
```

**Type 4 NDEF**

```swift
let reader = Type4Reader(transport: transport)
let ndef   = try await reader.readNDEF()
try await reader.writeNDEF(message)
```

**My Number Card (Japan)**

```swift
let data = try await CoreExtendedNFC.readMyNumberCard(
    items: [.tokenInfo, .individualNumber],
    cardInfoInputSupportPIN: "1234"
)
print(data.tokenInfo ?? "-", data.individualNumber ?? "-")
```

Official applet/data layout reference: `docs/MyNumber-Card-Data-Format.md`

**Card Identification (pure logic, no hardware)**

```swift
let type = CardIdentifier.identify(atqa: Data([0x00, 0x44]), sak: 0x00)
// → .mifareUltralight
```

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/Lakr233/CoreExtendedNFC.git", from: "0.1.0"),
]
```

Requires iOS 15+, Swift 6.2+, Xcode 16+.

Your host app needs:

- `NFC Tag Reading` capability
- `NFCReaderUsageDescription` in Info.plist
- `com.apple.developer.nfc.readersession.formats` set to `TAG`
- FeliCa system codes and ISO 7816 AIDs in Info.plist as needed
- See `docs/NFC-InfoPlist-Reference.md` for copy-paste values, meanings, and public GitHub examples

See `Example/` for a working configuration.

## Architecture

```
Sources/CoreExtendedNFC/
├── Transport/     CoreNFC wrappers (only layer that imports CoreNFC)
├── Protocol/      CRC, card ID, APDU builder, ASN.1, NDEF
├── Cards/
│   ├── MiFareUltralight/   READ, WRITE, FAST_READ, PWD_AUTH, memory maps
│   ├── NTAG/               READ_SIG, READ_CNT, variant detection
│   ├── DESFire/            Native commands, AF chaining, app/file ops, auth
│   ├── FeliCa/             Service probing, Type 3 NDEF, frame assembly
│   ├── ISO15693/           System info, block R/W, lock status
│   ├── Type4/              CC parsing, NDEF via SELECT/READ BINARY
│   ├── IndividualNumber/   Japanese My Number APDU flows
│   └── Passport/           BAC, PACE, Secure Messaging, DG parsers, AA/PA
├── Crypto/        AES-CMAC, ISO 9797 MAC, key derivation, SHA, 3DES
├── Models/        CardType, CardInfo, MemoryDump, MRZ, PassportModel
└── Utilities/     Hex, byte, parity
```

Only `Transport/` imports CoreNFC. Everything else is pure logic and fully testable with `MockTransport`.

## Testing

```bash
swift test    # 319 tests, 30 suites
```

All test vectors are sourced from public standards (ICAO 9303, NIST FIPS, NXP datasheets, RFCs). See [Test-Provenance.md](Research/Test-Provenance.md).

Real-world card validation is listed in [Tested Cards](docs/Tested-Cards.md) (24 exported scans across Ultralight, NTAG, DESFire, Type 4, FeliCa, and ISO 15693 tags).

> Testing is still in early stages — most coverage is against mock transports and standard test vectors, not exhaustive real-world hardware. If you run into issues with a specific card or passport, please [open an issue](https://github.com/Lakr233/CoreExtendedNFC/issues).

## Standards

ICAO 9303 (Parts 3/10/11) · BSI TR-03110 · ISO 7816-4 · ISO 14443-3 · ISO 9797-1 · RFC 4493 · RFC 5652 · NFC Forum Type 3/4 · NXP AN10833

## License

MIT
