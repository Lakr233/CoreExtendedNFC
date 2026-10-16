import Foundation

/// CoreExtendedNFC — high-level API for NFC tag operations on iOS.
///
/// Provides card identification, command construction, memory models,
/// and dump/restore orchestration on top of CoreNFC's RF transport.
public enum CoreExtendedNFC {
    /// Scan for any NFC tag, identify it, and return card info + transport.
    ///
    /// The returned ``NFCSessionManager`` keeps the NFC session alive.
    /// Call ``NFCSessionManager/invalidate()`` when you are done with the transport.
    ///
    /// - Throws: ``NFCError``. When the user dismisses the NFC sheet or the calling task
    ///   is cancelled, the error's ``Swift/Error/isNFCCancellation`` is `true`; apps
    ///   usually stay silent then.
    public static func scan(
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport, NFCSessionManager) {
        let manager = NFCSessionManager()
        let (info, transport) = try await manager.scan(message: message)

        do {
            let refinedInfo = try await refineCardInfo(info, transport: transport)
            manager.setAlertMessage(String(localized: "Detected \(refinedInfo.type.description)", bundle: .module))
            return (refinedInfo, transport, manager)
        } catch {
            // Never leave the system NFC sheet open when the caller gets no manager back.
            throw manager.invalidateAfterFailure(error)
        }
    }

    /// Scan and automatically dump the card's full memory.
    public static func scanAndDump(
        message: String? = nil
    ) async throws -> (CardInfo, MemoryDump) {
        let (info, transport, manager) = try await scan(message: message)

        // Non-operable cards (Classic, etc.) — return identification only
        guard info.type.isOperableOnIOS else {
            manager.invalidate()
            return (info, MemoryDump(cardInfo: info))
        }

        do {
            manager.setAlertMessage(String(localized: "Reading...", bundle: .module))
            let dump = try await dumpCard(info: info, transport: transport)
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return (info, dump)
        } catch {
            throw manager.invalidateAfterFailure(error)
        }
    }

    /// Refine a coarse scan classification using family-specific probes.
    public static func refineCardInfo(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        let refined = try await CardInfoRefiner.refine(info, transport: transport)
        if refined.type != info.type {
            NFCLog.info("Refined \(info.type.description) → \(refined.type.description)", source: "Core")
        }
        return refined
    }

    // MARK: - Passport / eMRTD

    /// Read data groups from an electronic passport or ID card.
    ///
    /// Performs BAC authentication using the MRZ key, then reads and parses
    /// the requested data groups from the chip.
    ///
    /// - Parameters:
    ///   - mrzKey: The MRZ key string (use ``MRZKeyGenerator/computeMRZKey(documentNumber:dateOfBirth:dateOfExpiry:)``).
    ///   - dataGroups: Which data groups to read (default: COM, DG1, DG2, SOD).
    ///   - message: The alert message shown during NFC scanning.
    /// - Returns: A ``PassportModel`` with all parsed data.
    /// - Throws: ``NFCError``. When the user dismisses the NFC sheet or the calling task
    ///   is cancelled, the error's ``Swift/Error/isNFCCancellation`` is `true`; apps
    ///   usually stay silent then.
    public static func readPassport(
        mrzKey: String,
        dataGroups: [DataGroupId] = [.com, .dg1, .dg2, .sod],
        performActiveAuth: Bool = true,
        trustAnchorsDER: [Data] = [],
        message: String? = nil,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> PassportModel {
        let manager = NFCSessionManager()
        let (_, transport) = try await manager.scan(for: [.iso14443], message: message ?? String(localized: "Hold your iPhone near your passport", bundle: .module))

        do {
            let reader = PassportReader(transport: transport)
            let passport = try await reader.readPassport(
                mrzKey: mrzKey,
                dataGroups: dataGroups,
                performActiveAuth: performActiveAuth,
                trustAnchorsDER: trustAnchorsDER,
                onProgress: { msg in
                    manager.setAlertMessage(msg)
                    onProgress?(msg)
                }
            )
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return passport
        } catch {
            throw manager.invalidateAfterFailure(error)
        }
    }
}
