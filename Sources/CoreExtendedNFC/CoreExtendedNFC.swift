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
    ///
    /// - Parameters:
    ///   - pollingTargets: Which tag technologies to poll for (default: all of them).
    ///     Narrow it, for example to `[.iso14443]`, to keep other tag types from
    ///     being detected.
    ///   - message: The alert message shown during NFC scanning.
    ///   - manager: The session manager that runs the scan. Pass your own instance,
    ///     or a subclass, to customize the session; it is returned unchanged.
    public static func scan(
        pollingTargets: [NFCSessionManager.PollingTarget] = [.all],
        message: String? = nil,
        manager: NFCSessionManager = NFCSessionManager()
    ) async throws -> (CardInfo, any NFCTagTransport, NFCSessionManager) {
        let (info, transport) = try await manager.scan(for: pollingTargets, message: message)

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
    ///
    /// - Parameters:
    ///   - pollingTargets: Which tag technologies to poll for (default: all of them).
    ///   - message: The alert message shown during NFC scanning.
    ///   - manager: The session manager that runs the scan. Pass your own instance,
    ///     or a subclass, to customize the session. It is invalidated before returning.
    public static func scanAndDump(
        pollingTargets: [NFCSessionManager.PollingTarget] = [.all],
        message: String? = nil,
        manager: NFCSessionManager = NFCSessionManager()
    ) async throws -> (CardInfo, MemoryDump) {
        let (info, transport, manager) = try await scan(
            pollingTargets: pollingTargets,
            message: message,
            manager: manager
        )

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
    ///   - dataGroups: Which data groups to read (default: EF.COM, DG1, DG2, EF.SOD).
    ///   - message: The alert message shown during NFC scanning.
    ///   - manager: The session manager that runs the scan. Pass your own instance,
    ///     or a subclass, to customize the session. It is invalidated before returning.
    ///   - onProgress: Called with each progress message, which is also shown on the NFC sheet.
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
        manager: NFCSessionManager = NFCSessionManager(),
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> PassportModel {
        let (_, transport) = try await manager.scan(for: [.iso14443], message: message ?? String(localized: "Hold your iPhone near your passport", bundle: .module))

        do {
            let passport = try await readPassport(
                transport: transport,
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

    /// Read data groups from an electronic passport or ID card over a transport you
    /// already hold, for example one returned by ``scan(pollingTargets:message:manager:)``.
    ///
    /// Runs the same workflow as ``readPassport(mrzKey:dataGroups:performActiveAuth:trustAnchorsDER:message:manager:onProgress:)``
    /// (EF.CardAccess, PACE or BAC, data groups, passive and Active Authentication) but
    /// neither starts nor ends an NFC session: updating the NFC sheet and invalidating
    /// the session are up to the caller.
    ///
    /// - Parameters:
    ///   - transport: A connected ISO 14443 (ISO 7816) transport to the document's chip.
    ///   - mrzKey: The MRZ key string (use ``MRZKeyGenerator/computeMRZKey(documentNumber:dateOfBirth:dateOfExpiry:)``).
    ///   - dataGroups: Which data groups to read (default: EF.COM, DG1, DG2, EF.SOD).
    ///   - performActiveAuth: Whether to attempt Active Authentication if DG15 is available.
    ///   - trustAnchorsDER: DER-encoded CSCA certificates used to validate the Document Signer certificate.
    ///   - onProgress: Called with each localized progress message.
    /// - Returns: A ``PassportModel`` with all parsed data.
    /// - Throws: ``NFCError`` or `CancellationError`.
    public static func readPassport(
        transport: any NFCTagTransport,
        mrzKey: String,
        dataGroups: [DataGroupId] = [.com, .dg1, .dg2, .sod],
        performActiveAuth: Bool = true,
        trustAnchorsDER: [Data] = [],
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> PassportModel {
        try await PassportReader(transport: transport).readPassport(
            mrzKey: mrzKey,
            dataGroups: dataGroups,
            performActiveAuth: performActiveAuth,
            trustAnchorsDER: trustAnchorsDER,
            onProgress: onProgress
        )
    }
}
