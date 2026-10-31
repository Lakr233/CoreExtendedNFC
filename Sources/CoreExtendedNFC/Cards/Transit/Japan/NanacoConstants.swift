import Foundation

/// Constants for Seven & i nanaco prepaid e-money cards in the FeliCa common area.
///
/// ## References
/// - TRETJapanNFCReader NanacoCardItemType / NanacoCardData: service codes, points, history types
/// - jennychan IC card format notes (iccard.jennychan.at-ninja.jp/format/nanaco.html): block layouts
public enum NanacoConstants {
    /// nanaco lives in the FeliCa common area (0xFE00).
    public static let systemCode = FeliCaCommonAreaConstants.systemCode

    // MARK: - Service Codes (little-endian)

    /// Purse service (1 block).
    public static let balanceServiceCode = Data([0x97, 0x55]) // 0x5597

    /// nanaco number service: block 0 bytes 0-7 hold the 16-digit number (BCD).
    public static let numberServiceCode = Data([0x8B, 0x55]) // 0x558B

    /// Card information service: block 0 bytes 0-1 last-use date, bytes 2-3 transaction
    /// sequence number, bytes 4-5 issue date.
    public static let infoServiceCode = Data([0xCB, 0x55]) // 0x55CB

    /// Points service: block 1 holds two point buckets.
    public static let pointsServiceCode = Data([0x0B, 0x56]) // 0x560B

    /// Transaction history service (cyclic read-only, newest first).
    public static let historyServiceCode = Data([0x4F, 0x56]) // 0x564F

    /// History records stored by the card.
    public static let maxHistoryBlocks = 5

    // MARK: - Block Layouts

    /// Balance block bytes 0-3: balance, little-endian (JPY).
    public static let balanceOffset = 0
    /// Card information block bytes 0-1: last-use date, year(7) month(4) day(5), base 2000.
    public static let lastUseDateOffset = 0
    /// Card information block bytes 4-5: issue date, same encoding as the last-use date.
    public static let issueDateOffset = 4
    /// Points block number within service 0x560B.
    public static let pointsBlockNumber: UInt16 = 1
    /// Points block bytes 0-2 and 5-7: the two point buckets, big-endian. Bytes 3-4 and 8-9
    /// hold their expiry dates.
    public static let pointsOffsets = [0, 5]

    // MARK: - History Block Layout (16 bytes, big-endian fields)

    /// Byte 0: usage type.
    public static let historyTypeOffset = 0
    /// Bytes 1-4: transaction amount (JPY).
    public static let historyAmountOffset = 1
    /// Bytes 5-8: balance after the transaction (JPY).
    public static let historyBalanceOffset = 5
    /// Bytes 9-12: date and time — year(11, base 2000) month(4) day(5) hour(6) minute(6),
    /// Japan Standard Time.
    public static let historyDateOffset = 9
    /// Bytes 13-14: transaction sequence number.
    public static let historySequenceOffset = 13

    // MARK: - Usage Types (history byte 0)

    /// Payment.
    public static let paymentType: UInt8 = 0x47
    /// Charges.
    public static let chargeTypes: Set<UInt8> = [0x5C, 0x6F, 0x70]
    /// Points exchanged for e-money, which adds value like a charge.
    public static let pointExchangeType: UInt8 = 0x83
    /// Balance transfer to or from another card; the direction is not known.
    public static let transferType: UInt8 = 0x35
}
