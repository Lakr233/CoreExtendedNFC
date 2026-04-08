import Foundation

enum MyNumberCardConstants {
    // MARK: - AIDs

    /// JPKI application.
    static let jpkiAID = Data([0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01])
    /// Card-info-input-support application.
    static let cardInfoInputSupportAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08])
    /// Individual-number application.
    static let individualNumberAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x01, 0x00])
    /// Card-info-input-check application.
    static let cardInfoInputCheckAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x01])

    static let allKnownAIDs = [
        jpkiAID,
        cardInfoInputSupportAID,
        individualNumberAID,
        cardInfoInputCheckAID,
    ]

    // MARK: - EF IDs

    static let jpkiTokenEFID = Data([0x00, 0x06])
    static let cardInfoInputSupportPINEFID = Data([0x00, 0x11])
    static let individualNumberEFID = Data([0x00, 0x01])

    static let remainingDigitalSignaturePINEFID = Data([0x00, 0x1B])
    static let remainingUserAuthenticationPINEFID = Data([0x00, 0x18])
    static let remainingCardInfoInputSupportPINEFID = Data([0x00, 0x11])
    static let remainingIndividualNumberPINEFID = Data([0x00, 0x1C])

    // MARK: - Payload lengths

    static let tokenLength: UInt8 = 20
    static let individualNumberLength: UInt8 = 17

    // MARK: - Official data format (EF 0001, individual number)

    /// Leading marker byte in the official EF 0001 payload.
    static let individualNumberHeaderByte: UInt8 = 0x10
    /// BER-TLV tag for individual number digits.
    static let individualNumberTag: UInt8 = 0x01
    /// BER-TLV length for the 12-digit individual number.
    static let individualNumberDigitsLength: UInt8 = 0x0C
    /// Number of numeric ASCII digits in the individual number field.
    static let individualNumberDigitsCount = 12
    /// Trailing status/reserved bytes in the official payload.
    static let individualNumberTrailerCount = 2
}
