import Foundation

/// Constants for Hong Kong Octopus FeliCa transit cards.
///
/// References:
/// - TRETJapanNFCReader OctopusCardItemType / OctopusCardData
/// - Metrodroid OctopusData
/// - FareBot OctopusData
/// - System code 0x8008, balance service 0x0117
enum OctopusConstants {
    /// Octopus FeliCa system code.
    static let systemCode = Data([0x80, 0x08])

    /// Balance service code 0x0117, encoded little-endian for CoreNFC.
    static let balanceServiceCode = Data([0x17, 0x01])

    /// Raw offset used for Octopus cards before the 2017 negative-balance change.
    static let pre2017BalanceRawOffset = 350

    /// Raw offset used for Octopus cards from 2017-10-01 onward.
    static let currentBalanceRawOffset = 500

    /// Compatibility alias for callers that explicitly request the older offset.
    static let legacyBalanceRawOffset = pre2017BalanceRawOffset

    /// Effective date of the Octopus maximum negative-balance change, in Hong Kong time.
    static let currentOffsetStartDate: Date = {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(identifier: "Asia/Hong_Kong")
        components.year = 2017
        components.month = 10
        components.day = 1
        return components.date ?? Date(timeIntervalSince1970: 1_506_787_200)
    }()

    static func balanceRawOffset(for scanDate: Date) -> Int {
        scanDate >= currentOffsetStartDate ? currentBalanceRawOffset : pre2017BalanceRawOffset
    }
}
