# Transit Card Research

Research date: 2026-05-09

This note captures the CardBal IDA findings, public implementation checks, and the CoreExtendedNFC changes made for the current transit-card balance work.

## CardBal IDA Source

CardBal was inspected through the local IDA MCP instance:

- IDB: `/Users/qaq/Desktop/cardbal.unfair-iossim.app/CardBal.i64`
- MCP endpoint: `http://127.0.0.1:13337/mcp`
- Binary: `CardBal`

Useful CardBal addresses:

| Area | Address | Finding |
| --- | ---: | --- |
| FeliCa profile table | `0x1002DD064` | Builds FeliCa transit-card profiles. |
| Japan Transit IC balance | `0x1002DD7E4` | Parses service `008B` balance from bytes 11-12, little-endian. |
| Octopus balance | `0x1002DDC08` | Parses service `0117` block 0 first four bytes, big-endian raw value. |
| Octopus offset | `0x1001A1AEC` | Returns raw offset `350` from 2010-12-01, legacy offset `35`. |
| Japan brand mapping | `0x1002DB5D8` | Maps issuer/operator hints such as `JE` to Suica, `JW` to ICOCA, `NR` to Nimoca. |
| Japan activity view | `0x100195994` | Shows `108F` history layout details. |
| T-Union AID gate | `0x1001D6A98` | Checks initial selected AID `A000000632010105`. |
| T-Union primary purse | `0x1001D7318` | Sends `80 5C 00 02`, `Le=04`. |
| T-Union negative purse | `0x1001D794C` | Sends `80 5C 01 02`, `Le=04`. |
| KSX6924 AID set | `0x1001726B8` | Includes Hyundai, T-Money, Cashbee, EB Card, Snapper/MOIBA, and K-Cash AIDs. |

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

CardBal and TRETJapanNFCReader agree on the card path:

- FeliCa system code: `8008`
- Balance service: `0117`, encoded for CoreNFC as `17 01`
- Balance block: block 0
- Raw value: first four bytes, big-endian
- Current offset: `350`
- Legacy offset: `35`
- Formula in HKD: `(raw - offset) / 10`

CoreExtendedNFC now adds `OctopusReader`, dispatches FeliCa system code `8008` to that reader, formats HKD balances, and logs raw block details. The unified `TransitBalance.balanceRaw` value stores cents, so the code uses `(raw - offset) * 10`.

### China T-Union, Shenzhen Tong, Nanjing

CardBal confirms the T-Union balance flow:

- AID: `A000000632010105`
- Primary purse APDU: `80 5C 00 02`, `Le=04`
- Negative purse APDU: `80 5C 01 02`, `Le=04`
- Final balance: primary purse minus negative purse
- Unit: CNY fen

CoreExtendedNFC now reads both purse slots and logs SELECT, each purse APDU response, and the final parsed value. Existing Shenzhen and Nanjing T-Union cards should follow this same AID path when the card exposes the national transport application.

The T-Union AID `A000000632010105` is required in the sample app polling identifiers for CoreNFC ISO 7816 APDU access. The older Shenzhen Tong AID `5041592E535A54` is also present for discovery and logging. Confirmed balance support uses the T-Union AID path above.

### Snapper / KSX6924

CardBal includes the KSX6924-family AID set:

- Hyundai: `A0000004520001`
- T-Money: `D4100000030001`
- Cashbee: `D4100000140001`
- EB Card: `D410000029000001`
- Snapper / MOIBA: `D4100000300001`
- K-Cash: `D4106509900020`

CoreExtendedNFC now tries these AIDs in that order and logs SELECT outcomes, balance APDU responses, and record reads. The balance APDU remains the KSX6924 command `90 4C 00 00`, `Le=04`.

## Researched Cards

| Card | Protocol reality | Current library handling |
| --- | --- | --- |
| EasyCard | Classic EasyCard is MIFARE Classic. Crypto1 authenticated reads sit outside iOS CoreNFC's public API. | Identification/logging path only. |
| Octopus | FeliCa system `8008`, service `0117`. | Implemented balance reader. |
| T-Union / Shenzhen / Nanjing | ISO 7816 AID `A000000632010105`, dual-purse balance. | Implemented dual-purse balance. |
| Singpass | Singpass is an identity/verification product. Singapore passport reading is eMRTD; CEPAS/EZ-Link uses separate transit-card AIDs. | Existing passport module covers eMRTD. CEPAS AID discovery was added for logs. |
| ICOCA | Japan Transit IC on FeliCa system `0003`. | Implemented via Japan IC reader with corrected offset. |
| Nimoca | Japan Transit IC on FeliCa system `0003`. | Implemented via Japan IC reader with corrected offset. |
| AT HOP | MIFARE DESFire EV1 with locked transit files. Public research exposes serial-level data more readily than balance. | DESFire identification/logging path. |
| Snapper | KSX6924-family card path in public research and CardBal AID table. | Added AID probing through KSX6924 reader. |

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
