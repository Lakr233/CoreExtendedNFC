import Foundation

/// Constants for China T-Union (交通联合) transit cards.
///
/// ## References
/// - T-Union AID: A000000632010105
/// - Metrodroid ChinaTransitData / TUnionTransitData
/// - NFSee: https://github.com/niceda/NFSee
///
/// ## Note
/// Beijing Yikatong uses a short AID which is blocked by CoreNFC on iOS.
/// Only T-Union branded cards with the full AID are supported.
enum TUnionConstants {
    /// T-Union application identifier.
    static let tUnionAID = Data([0xA0, 0x00, 0x00, 0x06, 0x32, 0x01, 0x01, 0x05])

    // MARK: - File IDs

    /// Main file containing balance, serial, and validity info.
    static let balanceFileID = Data([0x00, 0x15])

    // MARK: - GET BALANCE Command

    /// Proprietary GET BALANCE: CLA=0x80 INS=0x5C P1=0x00 P2=0x02.
    static let GET_BALANCE_CLA: UInt8 = 0x80
    static let GET_BALANCE_INS: UInt8 = 0x5C
    static let GET_BALANCE_P1: UInt8 = 0x00
    static let GET_BALANCE_P2: UInt8 = 0x02
    static let GET_BALANCE_LE: UInt8 = 0x04

    // MARK: - File 0x15 Layout

    /// Serial number: bytes 10-19 (10 bytes hex, skip first nibble per convention).
    static let serialOffset = 10
    static let serialLength = 10
    /// Validity start: bytes 20-23 (4 bytes hex date YYYYMMDD).
    static let validFromOffset = 20
    static let validFromLength = 4
    /// Validity end: bytes 24-27 (4 bytes hex date YYYYMMDD).
    static let validUntilOffset = 24
    static let validUntilLength = 4
}
