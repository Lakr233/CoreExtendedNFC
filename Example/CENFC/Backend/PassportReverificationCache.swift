import CoreExtendedNFC
import Foundation

/// In-memory cache of passive authentication re-run for imported passport records.
///
/// Re-verification hashes every data group and checks the SOD signature with
/// OpenSSL, so it runs once per record off the main thread and is kept here for
/// the rest of the app's life. Nothing is persisted: a stored result could be
/// edited just like the file's own report.
final class PassportReverificationCache {
    static let shared = PassportReverificationCache()

    private struct Entry {
        /// The bytes the result was computed from; an import that replaces a
        /// record keeps its ID, so the ID alone is not enough.
        let rawDataGroups: [DataGroupId: Data]
        let sodRaw: Data?
        let result: PassportSecurityStageResult
    }

    private var entries: [UUID: Entry] = [:]

    func cachedResult(for record: PassportRecord) -> PassportSecurityStageResult? {
        guard let entry = entries[record.id],
              entry.rawDataGroups == record.passport.rawDataGroups,
              entry.sodRaw == record.passport.sodRaw
        else { return nil }
        return entry.result
    }

    /// The re-verified passive authentication stage for `record`, computed off the main thread once.
    func passiveAuthentication(for record: PassportRecord) async -> PassportSecurityStageResult {
        if let cached = cachedResult(for: record) {
            return cached
        }
        let result = await Task.detached(priority: .userInitiated) {
            record.reverifiedPassiveAuthentication()
        }.value
        entries[record.id] = Entry(
            rawDataGroups: record.passport.rawDataGroups,
            sodRaw: record.passport.sodRaw,
            result: result
        )
        return result
    }
}
