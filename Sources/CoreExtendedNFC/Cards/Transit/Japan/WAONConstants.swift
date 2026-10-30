import Foundation

/// Constants for AEON WAON prepaid e-money cards in the FeliCa common area.
///
/// ## References
/// - TRETJapanNFCReader WaonCardItemType / WaonCardData: service codes, points, history types
/// - jennychan IC card format notes (iccard.jennychan.at-ninja.jp/format/waon.html): block
///   layouts and the packed history fields
/// - WDIC "WAON": service list and balance block layout
public enum WAONConstants {
    /// WAON lives in the FeliCa common area (0xFE00).
    public static let systemCode = FeliCaCommonAreaConstants.systemCode

    // MARK: - Service Codes (little-endian)

    /// Purse service (1 block).
    public static let balanceServiceCode = Data([0x17, 0x68]) // 0x6817

    /// WAON number service: block 0 bytes 0-7 hold the 16-digit number (BCD).
    public static let numberServiceCode = Data([0x4F, 0x68]) // 0x684F

    /// Points service: block 0 bytes 0-2 hold the point balance (big-endian, as TRETJapanNFCReader reads it).
    public static let pointsServiceCode = Data([0x4B, 0x68]) // 0x684B

    /// Transaction history service: 32-byte records split over pairs of blocks.
    public static let historyServiceCode = Data([0x0B, 0x68]) // 0x680B

    /// History records stored by the card (blocks 0-5; blocks 6-8 hold other data).
    public static let maxHistoryRecords = 3

    // MARK: - Balance Block (0x6817 block 0)

    /// Bytes 0-1: balance, little-endian (JPY). WAON caps the balance at ¥50,000.
    public static let balanceOffset = 0

    // MARK: - History Record Layout (32 bytes = 2 blocks)

    /// Bytes 0-12: terminal number.
    public static let historyTerminalRange = 0 ..< 13
    /// Bytes 13-14: card transaction sequence number.
    public static let historySequenceRange = 13 ..< 15
    /// Byte 17: usage type.
    public static let historyTypeOffset = 17
    /// Bytes 18-28: packed MSB-first bit fields — year(5, base 2005) month(4) day(5) hour(5)
    /// minute(6) balance(18) usage amount(18) charge amount(17), Japan Standard Time.
    public static let historyPackedOffset = 18

    // MARK: - Usage Types (history byte 17)

    /// Payment; the usage amount is the amount paid.
    public static let paymentType: UInt8 = 0x04
    /// Charges; the charge amount is the amount added.
    public static let chargeTypes: Set<UInt8> = [0x0C, 0x10]
    /// Other types named by TRETJapanNFCReader (WaonCardTransactionType). They are reported as
    /// `.unknown` with this name in `metadata["event"]`.
    public static let otherTypeNames: [UInt8: String] = [
        0x08: "return",
        0x18: "pointDownload",
        0x1C: "autoCharge",
        0x20: "autoCharge",
        0x28: "refund",
        0x30: "autoCharge",
        0x3C: "moveToNewCard",
        0x7C: "pointExchange",
    ]
}
