# My Number Card Data Format

This page summarizes the Japanese Individual Number Card (My Number card) data layout used by the reader in this repository.

The flow targets official card applets used for JPKI and card-info-input-support workflows:

- JPKI applet AID: `D392F000260100000001`
- Card-info-input-support applet AID: `D3921000310001010408`
- Individual-number applet AID: `D3921000310001010100`

## APDU Flow

### Token info (`EF 0006`)

1. `SELECT` JPKI applet (`D392F000260100000001`)
2. `SELECT` EF `0006`
3. `READ BINARY` length `0x14` (20 bytes)

Expected payload:

- 20-byte ASCII token text, typically space-padded.
- Example: `4A504B494150494343544F4B454E322020202020` (`"JPKIAPICCTOKEN2     "`).

### Individual number (`EF 0001`)

1. `SELECT` card-info-input-support applet (`D3921000310001010408`)
2. `SELECT` EF `0011` (PIN domain)
3. `VERIFY` with 4-digit card-info-input-support PIN (ASCII digits)
4. `SELECT` EF `0001`
5. `READ BINARY` length `0x11` (17 bytes)

Official payload layout (`EF 0001`, 17 bytes):

- Byte 0: `0x10` (header marker)
- Byte 1: `0x01` (tag)
- Byte 2: `0x0C` (length: 12)
- Bytes 3..14: 12-byte ASCII digits (the individual number)
- Bytes 15..16: trailing status/reserved bytes

Example (`123456789012`):

- Hex: `10 01 0C 31 32 33 34 35 36 37 38 39 30 31 32 00 00`

## Parsing Behavior in CoreExtendedNFC

- If payload shape is `17` bytes and header is `0x10`, parser enforces the official layout above.
- For non-official/legacy payloads, parser keeps a compatibility fallback (`TLV` parse then digit regex).
