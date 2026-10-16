import Foundation

/// Constants for China T-Union (交通联合) transit cards.
///
/// ## References
/// - T-Union AID: A000000632010105
/// - Metrodroid ChinaTransitData / TUnionTransitData
/// - FareBot ChinaCard / TUnionTransitInfo
/// - NFSee: https://github.com/niceda/NFSee
///
/// ## Note
/// Beijing Yikatong uses a short AID which is blocked by CoreNFC on iOS.
/// Only T-Union branded cards with the full AID are supported.
public enum TUnionConstants {
    /// T-Union application identifier.
    public static let tUnionAID = Data([0xA0, 0x00, 0x00, 0x06, 0x32, 0x01, 0x01, 0x05])

    // MARK: - File IDs

    /// Main file containing serial and validity info.
    public static let balanceFileID = Data([0x00, 0x15])
    public static let file15SFIReadP1: UInt8 = 0x95

    /// T-Union transaction record SFI. CardBal documents this as a circular
    /// 0x17-byte transaction/top-up record file.
    public static let transactionSFI: UInt8 = 0x18
    public static let transactionRecordLength: UInt8 = 0x17
    public static let maxTransactionRecords = 10

    /// T-Union transit activity SFI. CardBal documents this as a circular
    /// 0x30-byte travel activity record file.
    public static let transitActivitySFI: UInt8 = 0x1E
    public static let transitActivityRecordLength: UInt8 = 0x30
    public static let maxTransitActivityRecords = 30

    // MARK: - GET BALANCE Command

    /// Proprietary GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02.
    public static let GET_BALANCE_CLA: UInt8 = 0x80
    public static let GET_BALANCE_INS: UInt8 = 0x5C
    public static let GET_BALANCE_P1: UInt8 = 0x00
    public static let GET_NEGATIVE_BALANCE_P1: UInt8 = 0x01
    public static let GET_BALANCE_P2: UInt8 = 0x02
    public static let GET_BALANCE_LE: UInt8 = 0x04

    // MARK: - File 0x15 Layout

    /// Serial number: bytes 10-19 (10 bytes hex, skip first nibble per convention).
    public static let serialOffset = 10
    public static let serialLength = 10
    /// Validity start: bytes 20-23 (4 bytes hex date YYYYMMDD).
    public static let validFromOffset = 20
    public static let validFromLength = 4
    /// Validity end: bytes 24-27 (4 bytes hex date YYYYMMDD).
    public static let validUntilOffset = 24
    public static let validUntilLength = 4

    // MARK: - Transaction Record Layout

    public static let transactionAmountOffset = 5
    public static let transactionAmountLength = 4
    public static let transactionTypeOffset = 9
    public static let transactionStationOffset = 10
    public static let transactionStationLength = 6
    public static let transactionDateTimeOffset = 16
    public static let transactionDateTimeLength = 7
    /// Transaction types that load value (JR/T 0025 / PBOC: 0x01 ED load, 0x02 EP load).
    public static let topUpTypes: Set<UInt8> = [0x01, 0x02]
}
