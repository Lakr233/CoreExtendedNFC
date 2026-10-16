import CoreNFC
import Foundation

/// Manages an `NFCTagReaderSession` and exposes detection through async/await.
/// The session stays active after detection so callers can keep using the transport.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
/// Override the `open` hooks (``identifyTag(_:monitor:)``, ``pollingOptions(from:)``,
/// ``sessionDidBecomeActive(_:)``, ...); session bookkeeping itself is not overridable.
open class NFCSessionManager: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
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

    /// Whether the user dismissed the current (or most recently ended) session from
    /// the system NFC sheet. Transports of that session already report later failures
    /// as ``NFCError/userCanceled``; this covers a failure that raced the cancel.
    public var wasCanceledByUser: Bool {
        scanState.currentMonitor?.userCanceled ?? false
    }

    /// Scan for a tag and return the identified card plus transport.
    /// Call ``invalidate()`` when follow-up operations are finished.
    ///
    /// The returned transport is only usable while this manager is alive: releasing the
    /// manager invalidates its session, so keep a reference for as long as you use it.
    ///
    /// Only one scan may be pending per manager; a concurrent call throws
    /// ``NFCError/scanInProgress``. Cancelling the calling task — while
    /// waiting for a tag or while the detected tag is being connected — invalidates
    /// the session and throws `CancellationError`. Ending a pending scan with
    /// ``invalidate()`` or ``invalidate(errorMessage:)`` throws
    /// ``NFCError/sessionInvalidatedByCaller``. All three report
    /// ``Swift/Error/isNFCCancellation`` as `true`.
    public func scan(
        for targets: [PollingTarget] = [.all],
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport) {
        try Task.checkCancellation()
        let scanID = scanState.makeScanID()
        defer { scanState.forgetCancellation(scanID: scanID) }
        let result: (CardInfo, any NFCTagTransport) = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard NFCTagReaderSession.readingAvailable else {
                    continuation.resume(throwing: NFCError.nfcNotAvailable)
                    return
                }
                guard !scanState.hasPendingScan else {
                    continuation.resume(throwing: NFCError.scanInProgress)
                    return
                }
                let pollingOptions = Self.pollingOptions(from: targets)
                guard let session = NFCTagReaderSession(
                    pollingOption: pollingOptions,
                    delegate: self
                ) else {
                    continuation.resume(throwing: NFCError.nfcNotAvailable)
                    return
                }

                let monitor = SessionTerminationMonitor()
                switch scanState.begin(scanID: scanID, session: session, monitor: monitor, continuation: continuation) {
                case .busy:
                    continuation.resume(throwing: NFCError.scanInProgress)
                case .cancelled:
                    continuation.resume(throwing: CancellationError())
                case let .started(replacedSession):
                    // A session left open by an earlier, completed scan is superseded.
                    replacedSession?.invalidate()
                    session.alertMessage = message ?? String(localized: "Hold your iPhone near the NFC tag", bundle: .module)
                    session.begin()
                    // A cancel that raced begin() already detached and invalidated the
                    // session before it started; make sure it does not keep polling.
                    if !scanState.isCurrent(session) {
                        session.invalidate()
                    }
                }
            }
        } onCancel: {
            guard let cancelled = scanState.cancel(scanID: scanID) else { return }
            cancelled.session?.invalidate()
            // A connecting scan's continuation is failed by its connect task.
            cancelled.continuation?.resume(throwing: CancellationError())
        }

        // Cancelled after the tag was connected but before this task resumed.
        if Task.isCancelled {
            scanState.detach(ifStartedBy: scanID)?.invalidate()
            throw CancellationError()
        }
        return result
    }

    /// Update the alert message shown on the NFC system UI.
    public func setAlertMessage(_ message: String) {
        scanState.currentSession?.alertMessage = message
    }

    /// Invalidate the session with a success checkmark.
    public func invalidate() {
        let (session, continuation) = scanState.detach()
        session?.invalidate()
        continuation?.resume(throwing: NFCError.sessionInvalidatedByCaller)
    }

    /// Invalidate the session showing an error message.
    public func invalidate(errorMessage: String) {
        let (session, continuation) = scanState.detach()
        session?.invalidate(errorMessage: errorMessage)
        continuation?.resume(throwing: NFCError.sessionInvalidatedByCaller)
    }

    /// End the session after a failed operation and return the error to rethrow.
    ///
    /// When the user dismissed the sheet (or the task was cancelled) the session is
    /// invalidated without an error message and ``NFCError/userCanceled`` (or the
    /// `CancellationError`) is returned, so a failure that raced the cancel is not
    /// shown to the user as a read error.
    open func invalidateAfterFailure(_ error: any Error) -> any Error {
        let outcome = Self.failureOutcome(for: error, userCanceled: wasCanceledByUser)
        if let message = outcome.alertMessage {
            invalidate(errorMessage: message)
        } else {
            invalidate()
        }
        return outcome.error
    }

    /// The error to rethrow and the message to show on the sheet (`nil` = none)
    /// for a failure that ended a session.
    open class func failureOutcome(
        for error: any Error,
        userCanceled: Bool
    ) -> (error: any Error, alertMessage: String?) {
        if error is CancellationError {
            return (error, nil)
        }
        if userCanceled {
            return (NFCError.userCanceled, nil)
        }
        if case NFCError.userCanceled = error {
            return (error, nil)
        }
        return (error, error.localizedDescription)
    }

    /// CoreNFC holds its delegate weakly, so a session must not outlive the manager:
    /// its transport stops working once the manager is released.
    deinit {
        let (session, continuation) = scanState.detach()
        session?.invalidate()
        continuation?.resume(throwing: NFCError.sessionInvalidated("NFCSessionManager was released"))
    }

    // MARK: - NFCTagReaderSessionDelegate

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        NFCLog.info("NFC session active, waiting for tag…", source: "Session")
        sessionDidBecomeActive(session)
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        NFCLog.info("Session invalidated: \(error.localizedDescription)", source: "Session")
        let mapped = Self.invalidationError(from: error)
        let userCanceled = (mapped as? NFCError)?.isUserCancellation == true
        // Callbacks from a session this manager no longer owns (for example after
        // `invalidate()` followed by a new `scan()`) must not touch the new scan.
        // A user cancel is recorded even when no scan is pending, so the transport's
        // in-flight and later commands report `.userCanceled`.
        if let continuation = scanState.sessionInvalidated(session, userCanceled: userCanceled) {
            continuation.resume(throwing: mapped)
        }
        sessionDidInvalidate(session, error: mapped)
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard scanState.isCurrent(session) else { return }
        guard let detectedTag = tags.first else {
            NFCLog.debug("No tags in detection batch, restarting polling", source: "Session")
            session.restartPolling()
            return
        }
        let monitor = scanState.currentMonitor
        let managerType = type(of: self)
        guard let continuation = scanState.takeContinuationForDetection(by: session) else { return }

        // CoreNFC session and tag objects are not Sendable. These immutable references
        // are used only by this task, which resumes the continuation exactly once.
        nonisolated(unsafe) let readerSession = session
        nonisolated(unsafe) let nfcTag = detectedTag
        let scanState = scanState
        Task { @Sendable in
            do {
                try await withNFCErrorMapping(monitor) {
                    try await readerSession.connect(to: nfcTag)
                }
                // The caller's task was cancelled while connecting: its cancel handler
                // has invalidated the session, so hand back no transport.
                guard scanState.finishConnecting(by: readerSession) else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let (cardInfo, transport) = try managerType.identifyTag(nfcTag, monitor: monitor)
                NFCLog.info("Tag detected: \(cardInfo.type.description) UID:\(NFCLog.payload(cardInfo.uid))", source: "Session")
                continuation.resume(returning: (cardInfo, transport))
            } catch {
                let cancelled = !scanState.finishConnecting(by: readerSession)
                NFCLog.error("Tag connection failed: \(error.localizedDescription)", source: "Session")
                readerSession.invalidate(errorMessage: error.localizedDescription)
                continuation.resume(throwing: cancelled ? CancellationError() : error)
            }
        }
    }

    // MARK: - Subclass Hooks

    /// Called after the session became active. Default: does nothing.
    open func sessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    /// Called after a session ended and any pending scan was failed, including a
    /// session this manager no longer owns. `error` is the mapped error
    /// (see ``invalidationError(from:)``). Default: does nothing.
    open func sessionDidInvalidate(_ session: NFCTagReaderSession, error: any Error) {}

    /// Map the error CoreNFC reports when a session ends to ``NFCError``.
    open class func invalidationError(from error: any Error) -> any Error {
        let mapped = NFCReaderErrorMapping.map(error, context: .sessionInvalidation)
        if mapped is NFCError {
            return mapped
        }
        return NFCError.sessionInvalidated(error.localizedDescription)
    }

    /// CoreNFC polling options for `targets`.
    open class func pollingOptions(from targets: [PollingTarget]) -> NFCTagReaderSession.PollingOption {
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

    /// Wrap a connected tag in a transport and describe it. Called on the connecting task.
    open class func identifyTag(_ tag: NFCTag, monitor: SessionTerminationMonitor?) throws -> (CardInfo, any NFCTagTransport) {
        switch tag {
        case let .miFare(mifareTag):
            let transport = MiFareTransport(tag: mifareTag, terminationMonitor: monitor)
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
            let transport = ISO7816Transport(tag: iso7816Tag, terminationMonitor: monitor)
            let info = CardInfo(
                type: .smartMX,
                uid: iso7816Tag.identifier,
                historicalBytes: iso7816Tag.historicalBytes,
                initialSelectedAID: iso7816Tag.initialSelectedAID
            )
            return (info, transport)

        case let .feliCa(felicaTag):
            let transport = FeliCaTransport(tag: felicaTag, terminationMonitor: monitor)
            let info = CardInfo(
                type: .felicaStandard,
                uid: felicaTag.currentIDm,
                systemCode: felicaTag.currentSystemCode,
                idm: felicaTag.currentIDm
            )
            return (info, transport)

        case let .iso15693(iso15693Tag):
            let transport = ISO15693Transport(tag: iso15693Tag, terminationMonitor: monitor)
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
