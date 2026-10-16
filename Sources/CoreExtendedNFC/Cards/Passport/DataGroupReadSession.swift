import Foundation

/// Bookkeeping for the data group loop of `PassportReader.readPassport`.
///
/// A data group the chip reports as absent or protected is marked unavailable and the
/// loop goes on. When secure messaging ends (MAC failure, SM status word, interrupted
/// exchange), the remaining data groups are marked not read and everything read so far
/// is kept. Session loss and cancellation propagate.
public struct DataGroupReadSession: Sendable {
    public let transport: SecureMessagingTransport
    public private(set) var rawDataGroups: [DataGroupId: Data] = [:]
    public private(set) var status: [DataGroupId: PassportDataGroupReadResult] = [:]
    /// Data groups listed in EF.COM, once COM was read and listed at least one.
    public private(set) var listedInCOM: Set<DataGroupId>?
    /// Data groups the SOD has a hash for, once the SOD was read and listed at least one.
    public private(set) var listedInSOD: Set<DataGroupId>?
    /// Why secure messaging ended, once it has.
    public private(set) var secureMessagingEnded: String?
    /// First error that cost a data group (anything but "not available").
    public private(set) var firstFailure: (any Error)?

    public init(transport: SecureMessagingTransport) {
        self.transport = transport
    }

    /// Whether EF.COM or the SOD lists `dgId`; `nil` when that is unknown.
    ///
    /// Either index listing `dgId` is enough. Only the SOD hash list, the authoritative
    /// index (ICAO 9303-10 §4.6.1), can rule a data group out: EF.COM may be incomplete,
    /// so a COM that omits `dgId` without a known SOD gives `nil`. An index that was not
    /// read, could not be parsed or lists nothing is unknown, never "lists nothing".
    public func isListed(_ dgId: DataGroupId) -> Bool? {
        if listedInCOM?.contains(dgId) == true || listedInSOD?.contains(dgId) == true { return true }
        return listedInSOD == nil ? nil : false
    }

    /// Whether the SOD should be read as an index before `dgId` is considered: EF.COM
    /// was read and omits `dgId`, and the SOD has not been tried yet.
    public func needsSODIndex(before dgId: DataGroupId) -> Bool {
        guard secureMessagingEnded == nil, dgId != .com, dgId != .sod,
              status[.sod] == nil, listedInSOD == nil,
              let listedInCOM
        else { return false }
        return !listedInCOM.contains(dgId)
    }

    /// Record that secure messaging ended outside a data group read (e.g. during AA).
    public mutating func markSecureMessagingEnded(_ reason: String) {
        if secureMessagingEnded == nil { secureMessagingEnded = reason }
    }

    /// Whether `dgId` should be selected. Records why when it should not.
    public mutating func shouldSelect(_ dgId: DataGroupId) -> Bool {
        if let secureMessagingEnded {
            status[dgId] = PassportDataGroupReadResult(
                state: .notRead,
                detail: "Secure messaging ended before this data group: \(secureMessagingEnded)"
            )
            return false
        }
        if dgId != .com, dgId != .sod, isListed(dgId) == false {
            let detail = listedInCOM != nil
                ? "Neither EF.COM nor the SOD lists \(dgId.name)."
                : "The SOD does not list \(dgId.name)."
            status[dgId] = PassportDataGroupReadResult(state: .notPresent, detail: detail)
            return false
        }
        return true
    }

    /// Run `body` to read `dgId` and record the outcome.
    public mutating func read(_ dgId: DataGroupId, _ body: () async throws -> Data) async throws {
        do {
            let data = try await body()
            rawDataGroups[dgId] = data
            status[dgId] = PassportDataGroupReadResult(state: .read, detail: "\(data.count) bytes")
            NFCLog.info("Read \(dgId.name): \(data.count) bytes", source: "Passport")
            if dgId == .com, let parsed = try? COMParser.parse(data), !parsed.dataGroups.isEmpty {
                listedInCOM = Set(parsed.dataGroups)
            }
            if dgId == .sod, let parsed = try? SODParser.parse(data), !parsed.dataGroupHashes.isEmpty {
                listedInSOD = Set(parsed.dataGroupHashes.keys)
            }
        } catch let NFCError.dataGroupNotAvailable(reason) {
            // A plain "not available" reply may itself be how a strict chip says the
            // session is gone; the transport decides (two plain errors in a row).
            if let ended = await transport.sessionEndedReason {
                secureMessagingEnded = ended
                status[dgId] = PassportDataGroupReadResult(
                    state: .notRead,
                    detail: "Secure messaging ended while reading this data group: \(ended) (\(reason))"
                )
            } else {
                status[dgId] = PassportDataGroupReadResult(state: .unavailable, detail: reason)
            }
        } catch {
            if isSessionTerminating(error) { throw error }
            if firstFailure == nil { firstFailure = error }
            let reason = error.localizedDescription
            NFCLog.error("Reading \(dgId.name) failed: \(reason)", source: "Passport")
            if await transport.isSessionEnded {
                secureMessagingEnded = reason
                status[dgId] = PassportDataGroupReadResult(
                    state: .notRead,
                    detail: "Secure messaging ended while reading this data group: \(reason)"
                )
            } else {
                status[dgId] = PassportDataGroupReadResult(state: .failed, detail: reason)
            }
        }
    }
}
