import Foundation

/// Constants for South Korea KS X 6924 transit cards (T-Money, Cashbee, etc.).
///
/// ## References
/// - KS X 6924: Korean transit card specification
/// - Metrodroid: https://github.com/metrodroid/metrodroid
/// - FareBot: https://github.com/codebutler/farebot
enum KSX6924Constants {
    // MARK: - Application Identifiers

    static let tMoneyAID = Data([0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01])
    static let cashbeeAID = Data([0xD4, 0x10, 0x00, 0x00, 0x14, 0x00, 0x01])
    static let moibaAID = Data([0xD4, 0x10, 0x00, 0x00, 0x30, 0x00, 0x01])
    static let kcashAID = Data([0xD4, 0x10, 0x65, 0x09, 0x90, 0x00, 0x20])

    static let allAIDs: [(name: String, aid: Data)] = [
        ("T-Money", tMoneyAID),
        ("Cashbee", cashbeeAID),
        ("MOIBA", moibaAID),
        ("K-Cash", kcashAID),
    ]

    // MARK: - Proprietary Commands (CLA = 0x90)

    static let CLA: UInt8 = 0x90
    static let INS_GET_BALANCE: UInt8 = 0x4C
    static let INS_GET_RECORD: UInt8 = 0x78
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

    // MARK: - Transaction Records

    /// Maximum number of transaction records to attempt reading.
    static let maxRecords = 16

    /// Record field offsets (16-byte record from INS 0x78).
    static let recordType = 0 // 1 byte: 1=trip, 2=topup
    static let recordBalance = 2 // 4 bytes BE (KRW)
    static let recordAmount = 6 // 4 bytes BE (KRW)
    static let recordDate = 10 // 4 bytes BCD YYYYMMDD
}
