import Foundation

public enum MyNumberCardConstants {
    // MARK: - AIDs

    /// JPKI application.
    public static let jpkiAID = Data([0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01])
    /// Card-info-input-support application.
    public static let cardInfoInputSupportAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08])
    /// Individual-number application.
    public static let individualNumberAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x01, 0x00])
    /// Card-info-input-check application.
    public static let cardInfoInputCheckAID = Data([0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x01])

    public static let allKnownAIDs = [
        jpkiAID,
        cardInfoInputSupportAID,
        individualNumberAID,
        cardInfoInputCheckAID,
    ]

    // MARK: - EF IDs

    public static let jpkiTokenEFID = Data([0x00, 0x06])
    public static let cardInfoInputSupportPINEFID = Data([0x00, 0x11])
    public static let individualNumberEFID = Data([0x00, 0x01])

    public static let remainingDigitalSignaturePINEFID = Data([0x00, 0x1B])
    public static let remainingUserAuthenticationPINEFID = Data([0x00, 0x18])
    public static let remainingCardInfoInputSupportPINEFID = Data([0x00, 0x11])
    public static let remainingIndividualNumberPINEFID = Data([0x00, 0x1C])

    // MARK: - Payload lengths

    public static let tokenLength: UInt8 = 20
    public static let individualNumberLength: UInt8 = 17

    // MARK: - Official data format (EF 0001, individual number)

    /// Leading marker byte in the official EF 0001 payload.
    public static let individualNumberHeaderByte: UInt8 = 0x10
    /// BER-TLV tag for individual number digits.
    public static let individualNumberTag: UInt8 = 0x01
    /// BER-TLV length for the 12-digit individual number.
    public static let individualNumberDigitsLength: UInt8 = 0x0C
    /// Number of numeric ASCII digits in the individual number field.
    public static let individualNumberDigitsCount = 12
    /// Trailing status/reserved bytes in the official payload.
    public static let individualNumberTrailerCount = 2
}
