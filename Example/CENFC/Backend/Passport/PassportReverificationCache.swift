import CoreExtendedNFC
import CryptoKit
import Foundation

/// In-memory cache of the security stages re-derived for imported passport
/// records: passive authentication re-run, and the stored Active Authentication
/// result re-judged against it (``PassportRecord/reverifiedSecurity()``).
///
/// Re-verification hashes every data group and checks the SOD signature with
/// OpenSSL, so it runs once per record off the main thread. Nothing is
/// persisted: a stored result could be edited just like the file's own report.
///
/// Entries hold a SHA-256 digest of the bytes the result was computed from,
/// not the data groups themselves, and are evicted when ``PassportStore``
/// removes or replaces the record. Concurrent requests for the same record
/// share one verification task.
final class PassportReverificationCache {
    static let shared = PassportReverificationCache()

    private struct Entry {
        /// ``digest(of:)`` of the bytes the result was computed from; an import
        /// that replaces a record keeps its ID, so the ID alone is not enough.
        let digest: Data
        let result: PassportRecord.ReverifiedSecurity
    }

    private struct InFlight {
        let digest: Data
        let task: Task<PassportRecord.ReverifiedSecurity, Never>
    }

    private var entries: [UUID: Entry] = [:]
    private var inFlight: [UUID: InFlight] = [:]

    init() {}

    /// SHA-256 over every raw data group (in ``DataGroupId`` order, each with
    /// its identifier and length), the SOD bytes and the stored AA result.
    nonisolated static func digest(of passport: PassportModel) -> Data {
        var hasher = SHA256()
        func append(_ tag: String, _ bytes: Data) {
            hasher.update(data: Data(tag.utf8))
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { hasher.update(bufferPointer: $0) }
            hasher.update(data: bytes)
        }
        for id in DataGroupId.allCases {
            if let bytes = passport.rawDataGroups[id] {
                append("dg:\(id.rawValue)", bytes)
            }
        }
        if let sod = passport.sodRaw {
            append("sodRaw", sod)
        }
        // The stored AA result is re-judged too, so it is part of the key.
        if let active = passport.activeAuthResult {
            append("aa", Data("\(active.success)|\(active.status.rawValue)|\(active.details)".utf8))
        }
        return Data(hasher.finalize())
    }

    func cachedResult(for record: PassportRecord) -> PassportSecurityStageResult? {
        cachedSecurity(for: record)?.passiveAuthentication
    }

    func cachedSecurity(for record: PassportRecord) -> PassportRecord.ReverifiedSecurity? {
        guard let entry = entries[record.id],
              entry.digest == Self.digest(of: record.passport)
        else { return nil }
        return entry.result
    }

    /// Whether a verification for the record with `id` is running.
    func isVerifying(_ id: UUID) -> Bool {
        inFlight[id] != nil
    }

    /// Whether a result is cached for the record with `id`, whatever its bytes.
    func hasEntry(for id: UUID) -> Bool {
        entries[id] != nil
    }

    /// The re-verified passive authentication stage for `record` (see ``security(for:)``).
    func passiveAuthentication(for record: PassportRecord) async -> PassportSecurityStageResult {
        await security(for: record).passiveAuthentication
    }

    /// The re-derived security stages for `record`, computed off the main thread
    /// once. A second call while the first is running waits for the same task.
    func security(for record: PassportRecord) async -> PassportRecord.ReverifiedSecurity {
        let digest = Self.digest(of: record.passport)
        if let entry = entries[record.id], entry.digest == digest {
            return entry.result
        }
        if let running = inFlight[record.id], running.digest == digest {
            return await running.task.value
        }
        let task = Task.detached(priority: .userInitiated) {
            record.reverifiedSecurity()
        }
        inFlight[record.id] = InFlight(digest: digest, task: task)
        let result = await task.value
        // Store it only if the record was not evicted or re-verified with
        // other bytes while this task ran.
        if let running = inFlight[record.id], running.digest == digest {
            inFlight[record.id] = nil
            entries[record.id] = Entry(digest: digest, result: result)
        }
        return result
    }

    /// Drops the result for the record with `id` (it was removed or replaced).
    func evict(_ id: UUID) {
        entries[id] = nil
        inFlight[id] = nil
    }
}
