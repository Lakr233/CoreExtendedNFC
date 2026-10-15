import CoreNFC
import Foundation

/// Manages an `NFCTagReaderSession` and exposes detection through async/await.
/// The session stays active after detection so callers can keep using the transport.
public final class NFCSessionManager: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    /// Which tag types to poll for.
    public enum PollingTarget: Sendable {
        case iso14443
        case iso18092
        case iso15693
        case all
    }

    /// Session and continuation bookkeeping, shared between the caller's task and the
    /// CoreNFC delegate queue. All access goes through its lock.
    private let scanState = ScanState<NFCTagReaderSession, (CardInfo, any NFCTagTransport)>()

    /// Scan for a tag and return the identified card plus transport.
    /// Call ``invalidate()`` when follow-up operations are finished.
    ///
    /// Only one scan may be pending per manager; a concurrent call throws
    /// ``NFCError/unsupportedOperation(_:)``. Cancelling the calling task
    /// invalidates the session and throws `CancellationError`.
    public func scan(
        for targets: [PollingTarget] = [.all],
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport) {
        try Task.checkCancellation()
        let scanID = scanState.makeScanID()
        defer { scanState.forgetCancellation(scanID: scanID) }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard NFCTagReaderSession.readingAvailable else {
                    continuation.resume(throwing: NFCError.nfcNotAvailable)
                    return
                }
                guard !scanState.hasPendingScan else {
                    continuation.resume(throwing: Self.scanInProgressError)
                    return
                }
                let pollingOptions = Self.pollingOptions(from: targets)
                guard let session = NFCTagReaderSession(
                    pollingOption: pollingOptions,
                    delegate: self
                ) else {
                    continuation.resume(throwing: NFCError.unsupportedOperation(
                        "NFC tag reading is not available on this device"
                    ))
                    return
                }

                switch scanState.begin(scanID: scanID, session: session, continuation: continuation) {
                case .busy:
                    continuation.resume(throwing: Self.scanInProgressError)
                case .cancelled:
                    continuation.resume(throwing: CancellationError())
                case let .started(replacedSession):
                    // A session left open by an earlier, completed scan is superseded.
                    replacedSession?.invalidate()
                    session.alertMessage = message ?? String(localized: "Hold your iPhone near the NFC tag", bundle: .module)
                    session.begin()
                }
            }
        } onCancel: {
            guard let cancelled = scanState.cancel(scanID: scanID) else { return }
            cancelled.session?.invalidate()
            cancelled.continuation.resume(throwing: CancellationError())
        }
    }

    /// Update the alert message shown on the NFC system UI.
    public func setAlertMessage(_ message: String) {
        scanState.currentSession?.alertMessage = message
    }

    /// Invalidate the session with a success checkmark.
    public func invalidate() {
        let (session, continuation) = scanState.detach()
        session?.invalidate()
        continuation?.resume(throwing: NFCError.sessionInvalidated("Session invalidated by the caller"))
    }

    /// Invalidate the session showing an error message.
    public func invalidate(errorMessage: String) {
        let (session, continuation) = scanState.detach()
        session?.invalidate(errorMessage: errorMessage)
        continuation?.resume(throwing: NFCError.sessionInvalidated(errorMessage))
    }

    // MARK: - NFCTagReaderSessionDelegate

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) {
        NFCLog.info("NFC session active, waiting for tag…", source: "Session")
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        NFCLog.info("Session invalidated: \(error.localizedDescription)", source: "Session")
        // Callbacks from a session this manager no longer owns (for example after
        // `invalidate()` followed by a new `scan()`) must not touch the new scan.
        guard let continuation = scanState.sessionInvalidated(session) else { return }
        continuation.resume(throwing: Self.invalidationError(from: error))
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard scanState.isCurrent(session) else { return }
        guard let detectedTag = tags.first else {
            NFCLog.debug("No tags in detection batch, restarting polling", source: "Session")
            session.restartPolling()
            return
        }
        guard let continuation = scanState.takeContinuationForDetection(by: session) else { return }

        // CoreNFC session and tag objects are not Sendable. These immutable references
        // are used only by this task, which resumes the continuation exactly once.
        nonisolated(unsafe) let readerSession = session
        nonisolated(unsafe) let nfcTag = detectedTag
        Task { @Sendable in
            do {
                try await withNFCErrorMapping {
                    try await readerSession.connect(to: nfcTag)
                }
                let (cardInfo, transport) = try Self.identifyTag(nfcTag)
                NFCLog.info("Tag detected: \(cardInfo.type.description) UID:\(cardInfo.uid.hexDump)", source: "Session")
                continuation.resume(returning: (cardInfo, transport))
            } catch {
                NFCLog.error("Tag connection failed: \(error.localizedDescription)", source: "Session")
                readerSession.invalidate(errorMessage: error.localizedDescription)
                continuation.resume(throwing: error)
            }
        }
    }

    /// Map the error CoreNFC reports when a session ends to ``NFCError``.
    static func invalidationError(from error: any Error) -> any Error {
        let mapped = NFCReaderErrorMapping.map(error)
        if mapped is NFCError {
            return mapped
        }
        return NFCError.sessionInvalidated(error.localizedDescription)
    }

    private static var scanInProgressError: NFCError {
        .unsupportedOperation("A scan is already in progress on this NFCSessionManager")
    }

    // MARK: - Private

    private static func pollingOptions(from targets: [PollingTarget]) -> NFCTagReaderSession.PollingOption {
        if targets.contains(.all) {
            return [.iso14443, .iso18092, .iso15693]
        }

        var options: NFCTagReaderSession.PollingOption = []
        for target in targets {
            switch target {
            case .iso14443:
                options.insert(.iso14443)
            case .iso18092:
                options.insert(.iso18092)
            case .iso15693:
                options.insert(.iso15693)
            case .all:
                break
            }
        }
        return options
    }

    private static func identifyTag(_ tag: NFCTag) throws -> (CardInfo, any NFCTagTransport) {
        switch tag {
        case let .miFare(mifareTag):
            let transport = MiFareTransport(tag: mifareTag)
            let cardType: CardType = switch mifareTag.mifareFamily {
            case .ultralight:
                .mifareUltralight
            case .desfire:
                .mifareDesfire
            case .plus:
                .mifarePlusSL3_2K
            default:
                // Unknown MiFare family is most likely a MIFARE Classic tag.
                .mifareClassic1K
            }
            let info = CardInfo(
                type: cardType,
                uid: mifareTag.identifier,
                historicalBytes: mifareTag.historicalBytes
            )
            return (info, transport)

        case let .iso7816(iso7816Tag):
            let transport = ISO7816Transport(tag: iso7816Tag)
            let info = CardInfo(
                type: .smartMX,
                uid: iso7816Tag.identifier,
                historicalBytes: iso7816Tag.historicalBytes,
                initialSelectedAID: iso7816Tag.initialSelectedAID
            )
            return (info, transport)

        case let .feliCa(felicaTag):
            let transport = FeliCaTransport(tag: felicaTag)
            let info = CardInfo(
                type: .felicaStandard,
                uid: felicaTag.currentIDm,
                systemCode: felicaTag.currentSystemCode,
                idm: felicaTag.currentIDm
            )
            return (info, transport)

        case let .iso15693(iso15693Tag):
            let transport = ISO15693Transport(tag: iso15693Tag)
            let info = CardInfo(
                type: .iso15693_generic,
                uid: iso15693Tag.identifier,
                icManufacturer: iso15693Tag.icManufacturerCode
            )
            return (info, transport)

        @unknown default:
            throw NFCError.tagNotSupported
        }
    }
}
