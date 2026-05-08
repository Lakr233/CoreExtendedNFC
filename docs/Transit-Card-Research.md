# Transit Card Research

Research date: 2026-05-09

This note captures the CardBal IDA findings, public implementation checks, and the CoreExtendedNFC changes made for the current transit-card balance work.

## Public Reference Sources

The transit readers are cross-checked against these open-source projects:

| Project    | Local clone           | Revision inspected                         | Useful areas                                                                                          |
| ---------- | --------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| Metrodroid | `/tmp/metrodroid-src` | `04a603ba639f7a270b7bdbf24158c7d601087c29` | EasyCard Classic layout, Octopus date-based offset, T-Union balance bit layout, KSX6924 card support. |
| FareBot    | `/tmp/farebot-src`    | `dc09f6f014ea3675b64bcd38335b4b78d77fa374` | Octopus offset tests, ISO 7816 transit-card scaffolding, China and KSX6924 card modules.              |

## CardBal IDA Source

CardBal was inspected through the local IDA MCP instance:

- IDB: `/Users/qaq/Desktop/cardbal.unfair-iossim.app/CardBal.i64`
- MCP endpoint: `http://127.0.0.1:13337/mcp`
- Binary: `CardBal`

Useful CardBal addresses:

| Area                     |       Address | Finding                                                                                                                   |
| ------------------------ | ------------: | ------------------------------------------------------------------------------------------------------------------------- |
| FeliCa profile table     | `0x1002DD064` | Builds FeliCa transit-card profiles.                                                                                      |
| Japan Transit IC balance | `0x1002DD7E4` | Parses service `008B` balance from bytes 11-12, little-endian.                                                            |
| Octopus balance          | `0x1002DDC08` | Parses service `0117` block 0 first four bytes, big-endian raw value.                                                     |
| Octopus offset           | `0x1001A1AEC` | Returns raw offset `350` from 2010-12-01, legacy offset `35`; runtime code follows the public 2017 offset schedule below. |
| Japan brand mapping      | `0x1002DB5D8` | Maps issuer/operator hints such as `JE` to Suica, `JW` to ICOCA, `NR` to Nimoca.                                          |
| Japan activity view      | `0x100195994` | Shows `108F` history layout details.                                                                                      |
| T-Union AID gate         | `0x1001D6A98` | Checks initial selected AID `A000000632010105`.                                                                           |
| T-Union primary purse    | `0x1001D7318` | Sends `80 5C 00 02`, `Le=04`.                                                                                             |
| T-Union negative purse   | `0x1001D794C` | Sends `80 5C 01 02`, `Le=04`.                                                                                             |
| KSX6924 AID set          | `0x1001726B8` | Includes Hyundai, T-Money, Cashbee, EB Card, Snapper/MOIBA, and K-Cash AIDs.                                              |

## Implemented Fixes

### Japan IC, ICOCA, Nimoca

CardBal confirms the standard Japan Transit IC balance path:

- FeliCa system code: `0003`
- Balance service: `008B`, encoded for CoreNFC as `8B 00`
- Balance bytes: block bytes 11-12
- Endianness: little-endian
- Unit: JPY

CoreExtendedNFC now reads the balance at offset `0x0B`, matching CardBal. The history read limit is also increased to 20 blocks. Extra logs now include system code, service request versions, raw balance block, raw history blocks, and parsed balance.

### Hong Kong Octopus

CardBal, Metrodroid, FareBot, and TRETJapanNFCReader agree on the card path:

- FeliCa system code: `8008`
- Balance service: `0117`, encoded for CoreNFC as `17 01`
- Balance block: block 0
- Raw value: first four bytes, big-endian
- Pre-2017 offset: `350`
- Current offset from 2017-10-01: `500`
- Formula in HKD cents: `(raw - offset) * 10`

CoreExtendedNFC now adds `OctopusReader`, dispatches FeliCa system code `8008` to that reader, formats HKD balances, and logs raw block details. The unified `TransitBalance.balanceRaw` value stores cents, and the reader chooses the raw offset from the scan date.

### China T-Union, Shenzhen Tong, Nanjing

CardBal confirms the T-Union balance flow:

- AID: `A000000632010105`
- Primary purse APDU: `80 5C 00 02`, `Le=04`
- Negative purse APDU: `80 5C 01 02`, `Le=04`
- Balance bytes: low 31 bits of the big-endian 4-byte response
- Final balance: primary purse when populated, otherwise primary purse minus negative purse
- Unit: CNY fen

Metrodroid documents the top bit as a spare/garbage bit, so CoreExtendedNFC masks with `0x7FFFFFFF` before displaying the value. CoreExtendedNFC reads both purse slots and logs SELECT, each purse APDU response, and the final parsed value. Existing Shenzhen and Nanjing T-Union cards should follow this same AID path when the card exposes the national transport application.

The T-Union AID `A000000632010105` is required in the sample app polling identifiers for CoreNFC ISO 7816 APDU access. The older Shenzhen Tong AID `5041592E535A54` is also present for discovery and logging. Confirmed balance support uses the T-Union AID path above.

### Snapper / KSX6924

CardBal includes the KSX6924-family AID set:

- Hyundai: `A0000004520001`
- T-Money: `D4100000030001`
- Cashbee: `D4100000140001`
- EB Card: `D410000029000001`
- Snapper / MOIBA: `D4100000300001`
- K-Cash: `D4106509900020`

CoreExtendedNFC now tries these AIDs in that order and logs SELECT outcomes, balance APDU responses, and record reads. The sample app `Info.plist` mirrors these AIDs so CoreNFC can surface and transceive with those ISO 7816 applications. The balance APDU remains the KSX6924 command `90 4C 00 00`, `Le=04`.

`KSX6924Reader` continues AID probing when a selectable application reports a recoverable SELECT status through either a response status word or an `unexpectedStatusWord` transport error.

### Taiwan EasyCard

Metrodroid exposes the old EasyCard Classic dump layout:

- Card family: MIFARE Classic, keys required
- Magic: sector 0 block 1 equals `0e140001070208030904081000000000`
- Balance: sector 2 block 0, offset 0, 4-byte little-endian TWD amount
- Refill: sector 2 block 2
- Transactions: sector 3 blocks 1-2, sector 4 blocks 0-2, sector 5 blocks 0-2
- Time: Taipei timezone, seconds since Unix epoch

CoreExtendedNFC formats `TWD` balances as `NT$` integer amounts, ready for a Classic dump parser that consumes already-decrypted dump data.

## Researched Cards

| Card                         | Protocol reality                                                                                                                  | Current library handling                                                       |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| EasyCard                     | Classic EasyCard is MIFARE Classic. Crypto1 authenticated reads sit outside iOS CoreNFC's public API.                             | Identification/logging path only.                                              |
| Octopus                      | FeliCa system `8008`, service `0117`.                                                                                             | Implemented balance reader.                                                    |
| T-Union / Shenzhen / Nanjing | ISO 7816 AID `A000000632010105`, dual-purse balance.                                                                              | Implemented dual-purse balance.                                                |
| Singpass                     | Singpass is an identity/verification product. Singapore passport reading is eMRTD; CEPAS/EZ-Link uses separate transit-card AIDs. | Existing passport module covers eMRTD. CEPAS AID discovery was added for logs. |
| ICOCA                        | Japan Transit IC on FeliCa system `0003`.                                                                                         | Implemented via Japan IC reader with corrected offset.                         |
| Nimoca                       | Japan Transit IC on FeliCa system `0003`.                                                                                         | Implemented via Japan IC reader with corrected offset.                         |
| AT HOP                       | MIFARE DESFire EV1 with locked transit files. Public research exposes serial-level data more readily than balance.                | DESFire identification/logging path.                                           |
| Snapper                      | KSX6924-family card path in public research and CardBal AID table.                                                                | Added AID probing through KSX6924 reader.                                      |

## Validation Notes

`swift test` is a macOS package invocation and fails because the macOS toolchain lacks CoreNFC. The project is iOS-only, so the validation target is:

```bash
xcodebuild -project Example/CENFC.xcodeproj -scheme CENFC -destination 'generic/platform=iOS Simulator' build
```

The iOS simulator build passed after these changes.

For the user's physical cards, the best next capture is one scan per card with NFC logging enabled. The key log fields are:

- FeliCa: system code, service versions, raw balance block, raw history blocks.
- ISO 7816: selected AID, APDU command path, status words, raw balance bytes.
- DESFire: selected applications and file metadata where available.
