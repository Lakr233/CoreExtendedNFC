import Foundation

/// Constants for Hong Kong Octopus FeliCa transit cards.
///
/// References:
/// - TRETJapanNFCReader OctopusCardItemType / OctopusCardData
/// - Octopus official FAQ for post-2017 HK$50 convenience-limit eligibility
/// - Metrodroid OctopusData and FareBot OctopusData for raw value layout
/// - System code 0x8008, balance service 0x0117
enum OctopusConstants {
    /// Octopus FeliCa system code.
    static let systemCode = Data([0x80, 0x08])

    /// Balance service code 0x0117, encoded little-endian for CoreNFC.
    static let balanceServiceCode = Data([0x17, 0x01])

    /// Default raw offset for physical Octopus cards when the issue class is unknown.
    static let defaultBalanceRawOffset = 350

    /// Raw offset for On-Loan Octopus cards issued from 2017-10-01 and mobile Octopus products.
    static let expandedConvenienceLimitBalanceRawOffset = 500

    /// Compatibility alias for callers that explicitly request the older physical-card offset.
    static let legacyBalanceRawOffset = defaultBalanceRawOffset

    /// Effective issue date for Octopus cards eligible for the HK$50 convenience limit, in Hong Kong time.
    static let expandedConvenienceLimitIssueDate: Date = {
        var components = DateComponents()
        components.calendar = Calendar(identifier: .gregorian)
        components.timeZone = TimeZone(identifier: "Asia/Hong_Kong")
        components.year = 2017
        components.month = 10
        components.day = 1
        return components.date ?? Date(timeIntervalSince1970: 1_506_787_200)
    }()

    static func balanceRawOffset(cardIssuedAt issueDate: Date) -> Int {
        issueDate >= expandedConvenienceLimitIssueDate ? expandedConvenienceLimitBalanceRawOffset : defaultBalanceRawOffset
    }
}
