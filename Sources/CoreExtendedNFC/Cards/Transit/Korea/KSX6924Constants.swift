import Foundation

/// Constants for South Korea KS X 6924 transit cards (T-Money, Cashbee, etc.).
///
/// ## References
/// - KS X 6924: Korean transit card specification
/// - Metrodroid: https://github.com/metrodroid/metrodroid
/// - FareBot: https://github.com/codebutler/farebot
enum KSX6924Constants {
    // MARK: - Application Identifiers

    /// T-Money. Snapper (Wellington, NZ) cards answer to the same AID (Metrodroid KSX6924Application).
    static let tMoneyAID = Data([0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01])
    static let cashbeeAID = Data([0xD4, 0x10, 0x00, 0x00, 0x14, 0x00, 0x01])
    /// MOIBA (Metrodroid KSX6924Application, untested there).
    static let moibaAID = Data([0xD4, 0x10, 0x00, 0x00, 0x30, 0x00, 0x01])
    static let kcashAID = Data([0xD4, 0x10, 0x65, 0x09, 0x90, 0x00, 0x20])
    static let hyundaiAID = Data([0xA0, 0x00, 0x00, 0x04, 0x52, 0x00, 0x01])
    static let ebAID = Data([0xD4, 0x10, 0x00, 0x00, 0x29, 0x00, 0x00, 0x01])

    static let tMoneyOrSnapperName = "T-Money / Snapper"

    static let allAIDs: [(name: String, aid: Data)] = [
        ("Hyundai Capital Services", hyundaiAID),
        (tMoneyOrSnapperName, tMoneyAID),
        ("Cashbee", cashbeeAID),
        ("MOIBA", moibaAID),
        ("EB Card", ebAID),
        ("K-Cash", kcashAID),
    ]

    // MARK: - Proprietary Commands (CLA = 0x90)

    static let CLA: UInt8 = 0x90
    static let INS_GET_BALANCE: UInt8 = 0x4C
    static let BALANCE_RESP_LEN: UInt8 = 0x04

    // MARK: - FCI Purse Info

    /// Tag for purse info inside the SELECT response FCI.
    static let PURSE_TAG: UInt = 0xB0

    /// Purse info field offsets.
    static let purseCardType = 0
    /// Card serial number: 8 bytes BCD starting at offset 4.
    static let purseCSN = 4
    static let purseCSNLength = 8
    /// Issue date: 4 bytes BCD YYYYMMDD at offset 17.
    static let purseIssueDate = 17
    /// Expiry date: 4 bytes BCD YYYYMMDD at offset 21.
    static let purseExpiryDate = 21

    // MARK: - Transaction Records (EF SFI 4, Metrodroid TMoneyTrip)

    /// Short file identifier of the transaction record file.
    static let transactionSFI: UInt8 = 0x04
    /// Maximum number of transaction records to attempt reading.
    static let maxRecords = 32

    /// Record field offsets within an SFI 4 record (46 bytes on T-Money).
    static let recordType = 0 // 1 byte: 1 = trip, 2 = top-up
    static let recordBalance = 2 // 4 bytes BE, balance after transaction
    static let recordCounter = 6 // 4 bytes BE, transaction counter
    static let recordCost = 10 // 4 bytes BE, unsigned cost
    static let recordDateTime = 26 // 7 bytes BCD YYYYMMDDhhmmss, Asia/Seoul
    static let recordDateTimeLength = 7
    static let recordMinimumLength = recordDateTime + recordDateTimeLength

    /// Snapper records are 46 bytes with bytes 26..<46 always 0xFF (Metrodroid SnapperTransitData.check).
    static let snapperRecordLength = 46
    static let snapperFillerRange = 26 ..< 46
}
