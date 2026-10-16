import Foundation

/// Constants for South Korea KS X 6924 transit cards (T-Money, Cashbee, etc.).
///
/// ## References
/// - KS X 6924: Korean transit card specification
/// - Metrodroid: https://github.com/metrodroid/metrodroid
/// - FareBot: https://github.com/codebutler/farebot
public enum KSX6924Constants {
    // MARK: - Application Identifiers

    /// T-Money. Snapper (Wellington, NZ) cards answer to the same AID (Metrodroid KSX6924Application).
    public static let tMoneyAID = Data([0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01])
    public static let cashbeeAID = Data([0xD4, 0x10, 0x00, 0x00, 0x14, 0x00, 0x01])
    /// MOIBA (Metrodroid KSX6924Application, untested there).
    public static let moibaAID = Data([0xD4, 0x10, 0x00, 0x00, 0x30, 0x00, 0x01])
    public static let kcashAID = Data([0xD4, 0x10, 0x65, 0x09, 0x90, 0x00, 0x20])
    public static let hyundaiAID = Data([0xA0, 0x00, 0x00, 0x04, 0x52, 0x00, 0x01])
    public static let ebAID = Data([0xD4, 0x10, 0x00, 0x00, 0x29, 0x00, 0x00, 0x01])

    public static let tMoneyOrSnapperName = "T-Money / Snapper"

    public static let allAIDs: [(name: String, aid: Data)] = [
        ("Hyundai Capital Services", hyundaiAID),
        (tMoneyOrSnapperName, tMoneyAID),
        ("Cashbee", cashbeeAID),
        ("MOIBA", moibaAID),
        ("EB Card", ebAID),
        ("K-Cash", kcashAID),
    ]

    // MARK: - Proprietary Commands (CLA = 0x90)

    public static let CLA: UInt8 = 0x90
    public static let INS_GET_BALANCE: UInt8 = 0x4C
    public static let BALANCE_RESP_LEN: UInt8 = 0x04

    // MARK: - FCI Purse Info

    /// Tag for purse info inside the SELECT response FCI.
    public static let PURSE_TAG: UInt = 0xB0

    /// Purse info field offsets.
    public static let purseCardType = 0
    /// Card serial number: 8 bytes BCD starting at offset 4.
    public static let purseCSN = 4
    public static let purseCSNLength = 8
    /// Issue date: 4 bytes BCD YYYYMMDD at offset 17.
    public static let purseIssueDate = 17
    /// Expiry date: 4 bytes BCD YYYYMMDD at offset 21.
    public static let purseExpiryDate = 21

    // MARK: - Transaction Records (EF SFI 4, Metrodroid TMoneyTrip)

    /// Short file identifier of the transaction record file.
    public static let transactionSFI: UInt8 = 0x04
    /// Maximum number of transaction records to attempt reading.
    public static let maxRecords = 32

    /// Record field offsets within an SFI 4 record (46 bytes on T-Money).
    public static let recordType = 0 // 1 byte: 1 = trip, 2 = top-up
    public static let recordBalance = 2 // 4 bytes BE, balance after transaction
    public static let recordCounter = 6 // 4 bytes BE, transaction counter
    public static let recordCost = 10 // 4 bytes BE, unsigned cost
    public static let recordDateTime = 26 // 7 bytes BCD YYYYMMDDhhmmss, Asia/Seoul
    public static let recordDateTimeLength = 7
    public static let recordMinimumLength = recordDateTime + recordDateTimeLength

    /// Snapper records are 46 bytes with bytes 26..<46 always 0xFF (Metrodroid SnapperTransitData.check).
    public static let snapperRecordLength = 46
    public static let snapperFillerRange = 26 ..< 46
}
