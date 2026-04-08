# NFC Info.plist Reference

This page documents the FeliCa system codes and ISO 7816 AIDs commonly added to iOS NFC apps.

These values belong in the **host app's** `Info.plist`, not in the Swift package itself. In this repository, the example app plist lives at `Example/CENFC/Resources/Info.plist`.

For iOS NFC apps you typically need:

- `NFCReaderUsageDescription` in `Info.plist`
- `com.apple.developer.nfc.readersession.felica.systemcodes` in `Info.plist` when scanning FeliCa system codes
- `com.apple.developer.nfc.readersession.iso7816.select-identifiers` in `Info.plist` when selecting ISO 7816 applications by AID
- `NFC Tag Reading` capability enabled in Xcode

> Apple will let you ship a broad list, but it is usually better to keep only the values your app actually uses.

## Broad Compatibility Example

These are the merged values collected from public iOS NFC apps and SDKs on GitHub, plus a few already present in local notes.

### `com.apple.developer.nfc.readersession.felica.systemcodes`

```xml
<key>com.apple.developer.nfc.readersession.felica.systemcodes</key>
<array>
	<string>0003</string>
	<string>FE00</string>
	<string>8008</string>
	<string>88B4</string>
	<string>12FC</string>
	<string>8005</string>
	<string>90B7</string>
	<string>927A</string>
	<string>86A7</string>
</array>
```

### `com.apple.developer.nfc.readersession.iso7816.select-identifiers`

```xml
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
	<string>D2760000850101</string>
	<string>315041592E5359532E4444463031</string>
	<string>A0000002471001</string>
	<string>A0000002472001</string>
	<string>A000000167455349474E</string>
	<string>A000000291</string>
	<string>A00000000386980701</string>
	<string>A0000004520001</string>
	<string>D4100000030001</string>
	<string>D4100000140001</string>
	<string>D410000029000001</string>
	<string>D2760000850100</string>
	<string>F049442E43484E</string>
	<string>A000000812010208</string>
	<string>A00000045645444C2D3031</string>
	<string>00000000000000</string>
	<string>A000000077030C60000000FE00000500</string>
	<string>E828BD080FA0000001674544415441</string>
	<string>A000000527471117</string>
	<string>A0000006472F0001</string>
	<string>A0000005272101</string>
	<string>A000000308</string>
	<string>A000000527200101</string>
	<string>A000000151000000</string>
	<string>D392F000260100000001</string>
	<string>D3921000310001010408</string>
	<string>D3921000310001010100</string>
	<string>D3921000310001010401</string>
</array>
```

## FeliCa System Codes

| Value  | Meaning / common use                             | Notes                                                                                          |
| ------ | ------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `0003` | Transit IC cards in Japan                        | Commonly used for Suica / PASMO / ICOCA-style balance reads.                                   |
| `FE00` | FeliCa common area                               | Often used by apps that need broad FeliCa discovery across multiple card families.             |
| `8008` | Octopus                                          | Seen in public iOS NFC examples targeting Hong Kong Octopus cards.                             |
| `88B4` | FeliCa Lite-S                                    | Common in demos that identify or test Sony FeliCa Lite-S tags.                                 |
| `12FC` | Commonly associated with WAON-style FeliCa usage | Public app configs include it, but exact issuer usage may vary by card generation.             |
| `8005` | Public sample value from iOS NFC OSS apps        | Included in `react-native-nfc-manager`; exact card family not clearly documented in that repo. |
| `90B7` | Public sample value from iOS NFC OSS apps        | Included in `react-native-nfc-manager`; exact card family not clearly documented in that repo. |
| `927A` | Public sample value from iOS NFC OSS apps        | Included in `react-native-nfc-manager`; exact card family not clearly documented in that repo. |
| `86A7` | Additional Suica-related community value         | Included in `react-native-nfc-manager`; often reported alongside Suica support.                |

## ISO 7816 AIDs

| Value                              | Meaning / common use                                          | Notes                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `D2760000850101`                   | NFC Forum NDEF Tag Application                                | Standard AID for selecting the NDEF application on Type 4 tags.                                        |
| `D2760000850100`                   | Related NFC Forum / DESFire-style application selection value | Seen in public iOS NFC configs; often paired with `D2760000850101`.                                    |
| `315041592E5359532E4444463031`     | EMV Payment System Environment (`1PAY.SYS.DDF01`)             | Standard payment-directory selection AID. Payment-tag workflows on iOS have separate API availability. |
| `A0000002471001`                   | ICAO eMRTD LDS application                                    | The standard passport / ePassport app AID.                                                             |
| `A0000002472001`                   | ICAO travel document auxiliary application                    | Commonly included by ID verification SDKs for passports and national ID cards.                         |
| `A000000167455349474E`             | eSign application                                             | The ASCII tail decodes to `ESIGN`. Common in European eID / signing-card configs.                      |
| `A000000291`                       | Calypso transit AID prefix                                    | Often used as a prefix-style match for Calypso transit cards.                                          |
| `A00000000386980701`               | UnionPay payment application                                  | Observed in packaged UnionPay-family iOS apps; exact post-select APDUs are issuer-specific.            |
| `A0000004520001`                   | Korean transit / stored-value ecosystem application           | Seen in public mobile NFC configs used for Korean transit cards.                                       |
| `D4100000030001`                   | Korean transit application                                    | Included by passport / identity apps that also support common transit-card detection.                  |
| `D4100000140001`                   | Korean transit application                                    | Commonly associated with Cashbee-family cards in public NFC examples.                                  |
| `D410000029000001`                 | Public sample AID from iOS NFC app configs                    | Preserved because it appears in community NFC setups; exact issuer mapping is still unclear.           |
| `F049442E43484E`                   | China document application (observed)                         | Seen in packaged Chinese iOS apps; likely document-related, inferred from the ASCII tail `ID.CHN`.     |
| `A000000812010208`                 | Tangem card application                                       | Documented by `tangem-sdk-ios`.                                                                        |
| `A00000045645444C2D3031`           | Dutch driving licence application                             | Used by public ID verification SDKs for Dutch mobile document reading.                                 |
| `00000000000000`                   | Catch-all root / issuer-specific selection value              | Used by several passport / ID SDKs when some documents respond from a root or proprietary app context. |
| `A000000077030C60000000FE00000500` | National eID application used by some European ID cards       | Seen in public ID-reading SDKs; issuer usage depends on the document.                                  |
| `E828BD080FA0000001674544415441`   | Proprietary eData / eID application                           | Seen in public ID-reading SDKs; the ASCII tail contains `EDATA`.                                       |
| `A000000527471117`                 | YubiKey Management application                                | Documented by `yubikit-ios`.                                                                           |
| `A0000006472F0001`                 | FIDO / U2F application                                        | Used by YubiKey and many FIDO-compatible security keys.                                                |
| `A0000005272101`                   | YubiKey OATH application                                      | Used for OATH HOTP / TOTP management over NFC.                                                         |
| `A000000308`                       | PIV application                                               | Used for PIV smart-card access, including YubiKey PIV.                                                 |
| `A000000527200101`                 | YubiKey OTP / HMAC-SHA1 application                           | Used for OTP and challenge-response flows.                                                             |
| `A000000151000000`                 | YubiKey Security Domain                                       | Used for management and secure-element administration flows.                                           |
| `D392F000260100000001`             | Japan My Number JPKI application                              | Used for token/certificate related flows on Japanese Individual Number cards.                          |
| `D3921000310001010408`             | Japan My Number card-info input support application           | Used to verify the card-info-input-support PIN before protected reads.                                 |
| `D3921000310001010100`             | Japan My Number individual-number application                 | Used in resident-registry / individual-number related flows.                                           |
| `D3921000310001010401`             | Japan My Number card-info input check application             | Companion applet observed in My Number card reader configurations.                                     |

## Public GitHub Sources

These repositories were used to verify real-world iOS NFC plist values:

- `https://github.com/revtel/react-native-nfc-manager`
- `https://github.com/Yubico/yubikit-ios`
- `https://github.com/Gimly-Blockchain/tangem-sdk-ios`
- `https://github.com/idnow/de.idnow.ios.sdk.spm`
- `https://github.com/onfido/onfido-ios-sdk`
- `https://github.com/batuhanoztrk/react-native-nfc-passport-reader`

## Apple Platform Notes

- Apple documents that `NFCTagReaderSession` / `NFCISO7816Tag` will issue `SELECT` for each AID in `com.apple.developer.nfc.readersession.iso7816.select-identifiers` and expose the first successful one through `initialSelectedAID`.
- Apple also documents that including `D2760000850101` causes matching DESFire Type 4 tags to be surfaced as `NFCISO7816Tag` instead of `NFCMiFareTag`.
- Apple documents that payment-tag support uses `NFCPaymentTagReaderSession`, and that API is only available in the EU.

## Handling Guidance

- `A0000002471001` and `D2760000850101` map cleanly to concrete library workflows today (`ePassport` and `Type 4 NDEF`).
- `315041592E5359532E4444463031`, `A00000000386980701`, and `F049442E43484E` are useful to include in `Info.plist` so the system can surface `initialSelectedAID`, but they should remain generic ISO 7816 cards unless your app implements issuer-specific APDU flows.
- `D392F000260100000001`, `D3921000310001010408`, `D3921000310001010100`, and `D3921000310001010401` are required for My Number card workflows on iOS; including all four mirrors working production reader configurations.
- The example app now surfaces these AIDs as “Known ISO 7816 Application” hints in the scan detail UI, while keeping unsupported payment / document cards on the safe generic path.

## Recommended Usage

- If your app only reads passports, start with `A0000002471001` and any additional document AIDs you specifically encounter.
- If your app only reads FIDO keys, keep the YubiKey / FIDO entries instead of the full list.
- If your app reads Japanese transit cards, keep the relevant FeliCa system codes instead of the full list.
- Save the final chosen values in the app target's `Info.plist`; for this repo's example app, that is `Example/CENFC/Resources/Info.plist`.
