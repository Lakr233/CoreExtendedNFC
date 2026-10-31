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

    // MARK: - Tap Records (EF SFI 3)

    /// Short file identifier of the boarding / alighting record file.
    public static let tapRecordSFI: UInt8 = 0x03
    /// SFI 3 records are 52 bytes on T-Money and Cashbee.
    public static let tapRecordLength = 52

    /// Tap record field offsets.
    public static let tapEvent = 2 // 1 byte: 0x00 tap on (boarding), 0x01 tap off (alighting)
    public static let tapStation = 5 // 4 bytes, station or stop identifier
    public static let tapModeCode = 9 // 2 bytes BE, KOTRIS transport code
    public static let tapDateTime = 11 // 7 bytes BCD YYYYMMDDhhmmss, or a 33-bit packed date-time
    public static let tapDistance = 19 // 2 bytes BE, distance travelled in metres

    /// Transport codes whose terminals write another clock format at ``tapDateTime``
    /// (CardBal's Mybi and Gwangju profiles). Only a BCD date-time is decoded for them.
    public static let bcdOnlyClockModeCodes: [ClosedRange<Int>] = [
        600 ... 619, 621 ... 660, 684 ... 685, 691 ... 691, 711 ... 713, 729 ... 729, 770 ... 799,
        870 ... 871, 877 ... 877, 887 ... 888, 901 ... 905, 909 ... 909, 913 ... 916, 925 ... 931,
        936 ... 936, 940 ... 940,
    ]

    // MARK: - KOTRIS Transport Codes

    /// Rail codes in KORAIL's KOTRIS public-transport code table (class `R`), plus Seoul
    /// Smart Card and Incheon Institute codes for 209, 210, 235 and 237.
    public static let kotrisRailCodes: [ClosedRange<Int>] = [
        200 ... 210, 231 ... 232, 235 ... 235, 237 ... 237, 440 ... 440, 691 ... 691, 699 ... 699,
        850 ... 851, 853 ... 853, 870 ... 872,
    ]

    /// Bus codes in the KOTRIS table (class `B`), plus Seoul Smart Card code 142
    /// and reviewed station-catalog codes 736 and 741.
    /// Codes 800-802 (Namsan tunnel tolls, parking, Manwolsan tunnel) are left out.
    public static let kotrisBusCodes: [ClosedRange<Int>] = [
        100 ... 106, 110 ... 110, 115 ... 115, 120 ... 122, 130 ... 134, 140 ... 140, 142 ... 142,
        151 ... 152, 400 ... 404, 406 ... 406, 408 ... 408, 430 ... 431, 450 ... 467, 470 ... 472,
        474 ... 477, 480 ... 491, 496 ... 496, 500 ... 546, 550 ... 550, 570 ... 570, 580 ... 584,
        599 ... 690, 692 ... 695, 701 ... 722, 729 ... 729, 736 ... 736, 741 ... 741, 770 ... 799,
        810 ... 820, 990 ... 999,
    ]

    /// Taxi codes in the KOTRIS table (class `T`).
    public static let kotrisTaxiCodes: [ClosedRange<Int>] = [300 ... 303, 321 ... 321]
}
