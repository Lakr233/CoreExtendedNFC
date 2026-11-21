import Foundation

/// The phrases of a ``DumpSummary``, from `Localizable.xcstrings`.
///
/// Counts use the catalog's plural variations, so English reads "1 page" and
/// "16 pages". ``english`` reads the English table with English plural rules
/// whatever the device language, for exports; ``current`` follows the user's
/// language.
struct DumpSummaryText: Sendable {
    let bundle: Bundle
    let locale: Locale

    static let english = language("en")

    /// The phrases of one language of the catalog, with that language's plural rules.
    static func language(_ identifier: String) -> DumpSummaryText {
        DumpSummaryText(
            bundle: Bundle.module.path(forResource: identifier, ofType: "lproj").flatMap(Bundle.init(path:)) ?? .module,
            locale: Locale(identifier: identifier)
        )
    }

    static var current: DumpSummaryText {
        DumpSummaryText(bundle: .module, locale: .current)
    }

    func pages(_ count: Int) -> String {
        String(localized: "\(count) pages", bundle: bundle, locale: locale, comment: "Dump size: Type 2 tag pages")
    }

    func blocks(_ count: Int) -> String {
        String(localized: "\(count) blocks", bundle: bundle, locale: locale, comment: "Dump size: memory blocks")
    }

    func files(_ count: Int) -> String {
        String(localized: "\(count) files", bundle: bundle, locale: locale, comment: "Dump size: Type 4 / DESFire files")
    }

    func ndefBytes(_ count: Int) -> String {
        String(localized: "\(count) NDEF bytes", bundle: bundle, locale: locale, comment: "Dump size: bytes of the NDEF message")
    }

    var identificationOnly: String {
        String(localized: "identification only", bundle: bundle, locale: locale, comment: "Dump size: no memory was read")
    }

    func exportBytes(_ count: Int) -> String {
        String(localized: "\(count)-byte export", bundle: bundle, locale: locale, comment: "Size of the binary export, as in \"16 pages, 64-byte export, and 1 NDEF record\"")
    }

    /// The parts of the technical summary as one phrase, such as
    /// "16 pages, 64-byte export, and 1 NDEF record" or "16 页、导出 64 字节和1 条 NDEF 记录".
    func list(_ parts: [String]) -> String {
        let formatter = ListFormatter()
        formatter.locale = locale
        return formatter.string(from: parts) ?? parts.joined(separator: ", ")
    }

    func ndefRecords(_ count: Int) -> String {
        String(localized: "\(count) NDEF records", bundle: bundle, locale: locale, comment: "Number of records in the NDEF message")
    }

    func type2Summary(_ storage: String) -> String {
        String(localized: "Read a Type 2 style memory map with \(storage).", bundle: bundle, locale: locale)
    }

    func type4Summary(_ storage: String) -> String {
        String(localized: "Read an NFC Forum Type 4 file layout with \(storage).", bundle: bundle, locale: locale)
    }

    func feliCaSummary(_ storage: String) -> String {
        String(localized: "Read FeliCa Type 3 blocks with \(storage).", bundle: bundle, locale: locale)
    }

    func iso15693Summary(_ storage: String) -> String {
        String(localized: "Read ISO 15693 vicinity memory with \(storage).", bundle: bundle, locale: locale)
    }

    func desfireSummary(_ storage: String) -> String {
        String(localized: "Enumerated DESFire applications and captured \(storage).", bundle: bundle, locale: locale)
    }

    var passportSummary: String {
        String(localized: "Passport chips use the dedicated eMRTD workflow instead of generic dump reads.", bundle: bundle, locale: locale)
    }

    func capturedSummary(_ storage: String, from card: String) -> String {
        String(localized: "Captured \(storage) from \(card).", bundle: bundle, locale: locale)
    }
}
