import Foundation

/// Constants for Rakuten Edy prepaid e-money cards in the FeliCa common area.
///
/// ## References
/// - Metrodroid EdyTransitData / EdyTrip: service codes, Edy ID, balance, history record layout
/// - TRETJapanNFCReader RakutenEdyCardItemType / RakutenEdyCardData
/// - jennychan IC card format notes (iccard.jennychan.at-ninja.jp/format/edy.html): issue date,
///   sequence number and sample history records
public enum EdyConstants {
    /// Edy lives in the FeliCa common area (0xFE00).
    public static let systemCode = FeliCaCommonAreaConstants.systemCode

    // MARK: - Service Codes (little-endian)

    /// Card information service (random read-only).
    public static let idServiceCode = Data([0x0B, 0x11]) // 0x110B

    /// Purse service (1 block).
    public static let balanceServiceCode = Data([0x17, 0x13]) // 0x1317

    /// Transaction history service (cyclic read-only, newest first).
    public static let historyServiceCode = Data([0x0F, 0x17]) // 0x170F

    /// History records stored by the card.
    public static let maxHistoryBlocks = 6

    // MARK: - Card Information Block (0x110B block 0)

    /// Bytes 2-9: Edy ID, the 16-digit number printed on the card (BCD).
    public static let idOffset = 2
    /// Length of the Edy ID in bytes.
    public static let idLength = 8
    /// Bytes 10-13: issue date and time, encoded like ``historyDateOffset``.
    public static let issueDateOffset = 10

    // MARK: - Balance Block (0x1317 block 0)

    /// Bytes 0-3: balance, little-endian (JPY).
    public static let balanceOffset = 0

    // MARK: - History Block Layout (16 bytes, big-endian fields)

    /// Byte 0: process type.
    public static let historyTypeOffset = 0
    /// Bytes 2-3: transaction sequence number (byte 1 is unknown and 00 in every sample).
    public static let historySequenceOffset = 2
    /// Bytes 4-7: date and time. The upper 15 bits count days since 2000-01-01 and the lower
    /// 17 bits count seconds since midnight, in Japan Standard Time. Zero means no date.
    public static let historyDateOffset = 4
    /// Bytes 8-11: transaction amount (JPY).
    public static let historyAmountOffset = 8
    /// Bytes 12-15: balance after the transaction (JPY).
    public static let historyBalanceOffset = 12

    // MARK: - Process Types (history byte 0)

    /// Payment.
    public static let paymentType: UInt8 = 0x20
    /// Charge (cash or Edy Viewer deposit).
    public static let chargeType: UInt8 = 0x02
    /// Edy Gift or value charge, which adds value like a charge.
    public static let giftType: UInt8 = 0x04
}
