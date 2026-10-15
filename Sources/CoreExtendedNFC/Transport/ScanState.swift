import Foundation

/// Lock-protected bookkeeping for ``NFCSessionManager``: the current reader
/// session, the pending scan continuation, and the scan whose tag is being connected.
///
/// Invariants:
/// - At most one scan is pending; a second ``begin(scanID:session:monitor:continuation:)`` is refused.
/// - A continuation is handed out at most once, so it is resumed exactly once.
/// - Callbacks from a session that is no longer current are ignored.
/// - A scan cancelled while its tag is being connected is reported by
///   ``finishConnecting(by:)``, so it ends with `CancellationError` instead of a live transport.
///
/// Generic over the session type so it can be unit-tested without CoreNFC.
final class ScanState<Session: AnyObject, Value>: @unchecked Sendable {
    typealias Continuation = CheckedContinuation<Value, any Error>

    enum BeginResult {
        /// The scan is registered. `replacedSession` is a still-open session from an
        /// earlier, already-completed scan that the caller should invalidate.
        case started(replacedSession: Session?)
        /// Another scan is still waiting for a tag.
        case busy
        /// The scan's task was cancelled before it could start.
        case cancelled
    }

    private struct Pending {
        let scanID: UInt64
        let continuation: Continuation
    }

    /// A detected tag whose connection is in progress. The continuation has already
    /// been handed to the connecting task.
    private struct Connecting {
        let scanID: UInt64
        let session: Session
        var cancelled = false
    }

    private struct State {
        var session: Session?
        /// The scan that started `session`.
        var sessionScanID: UInt64?
        /// Termination record of `session`; kept after the session ends so the
        /// manager can still report whether the user cancelled it.
        var monitor: SessionTerminationMonitor?
        var pending: Pending?
        var connecting: Connecting?
        var nextScanID: UInt64 = 1
        var cancelledScanIDs: Set<UInt64> = []
    }

    private let state = LockedValue(State())

    /// Reserve an identifier for a scan before it starts, so cancellation that
    /// races ahead of ``begin(scanID:session:monitor:continuation:)`` is still observed.
    func makeScanID() -> UInt64 {
        state.withLock { state in
            defer { state.nextScanID += 1 }
            return state.nextScanID
        }
    }

    /// Whether a scan is currently waiting for a tag.
    var hasPendingScan: Bool {
        state.withLock { $0.pending != nil }
    }

    /// The session currently owned by the manager.
    var currentSession: Session? {
        state.withLock { $0.session }
    }

    /// Termination record of the current (or most recently ended) session.
    var currentMonitor: SessionTerminationMonitor? {
        state.withLock { $0.monitor }
    }

    func begin(
        scanID: UInt64,
        session: Session,
        monitor: SessionTerminationMonitor? = nil,
        continuation: Continuation
    ) -> BeginResult {
        state.withLock { state in
            if state.cancelledScanIDs.remove(scanID) != nil {
                return .cancelled
            }
            guard state.pending == nil else { return .busy }
            let replaced = state.session === session ? nil : state.session
            state.session = session
            state.sessionScanID = scanID
            state.monitor = monitor
            state.pending = Pending(scanID: scanID, continuation: continuation)
            return .started(replacedSession: replaced)
        }
    }

    /// Whether `session` is the manager's current session.
    func isCurrent(_ session: Session) -> Bool {
        state.withLock { $0.session === session }
    }

    /// A tag was detected by `session`. Returns the continuation to resume, or `nil`
    /// if the session is stale or no scan is pending. The scan then counts as
    /// connecting until ``finishConnecting(by:)``.
    func takeContinuationForDetection(by session: Session) -> Continuation? {
        state.withLock { state in
            guard state.session === session, let pending = state.pending else { return nil }
            state.pending = nil
            state.connecting = Connecting(scanID: pending.scanID, session: session)
            return pending.continuation
        }
    }

    /// The connection attempt started by ``takeContinuationForDetection(by:)`` ended.
    /// Returns `false` when the scan was cancelled meanwhile; the caller must then
    /// fail the continuation with `CancellationError` instead of returning a transport.
    func finishConnecting(by session: Session) -> Bool {
        state.withLock { state in
            guard let connecting = state.connecting, connecting.session === session else { return true }
            state.connecting = nil
            return !connecting.cancelled
        }
    }

    /// `session` was invalidated by the system. Returns the pending continuation to fail,
    /// or `nil` for a stale session (one that is no longer current) or when no scan is
    /// pending. When `userCanceled` is set and `session` is current, the user cancel is
    /// recorded on the session's monitor even if nothing is pending, so commands that
    /// fail afterwards report ``NFCError/userCanceled``.
    func sessionInvalidated(_ session: Session, userCanceled: Bool = false) -> Continuation? {
        state.withLock { state in
            guard state.session === session else { return nil }
            if userCanceled {
                state.monitor?.recordUserCancel()
            }
            state.session = nil
            let pending = state.pending
            state.pending = nil
            return pending?.continuation
        }
    }

    /// Detach the current session (the caller invalidates it) and any pending continuation
    /// (the caller fails it), because the system's invalidation callback for that session
    /// will be ignored as stale.
    func detach() -> (session: Session?, continuation: Continuation?) {
        state.withLock { state in
            let session = state.session
            let pending = state.pending
            state.session = nil
            state.pending = nil
            return (session, pending?.continuation)
        }
    }

    /// Detach the current session only if it was started by scan `scanID`, and return
    /// it for the caller to invalidate.
    func detach(ifStartedBy scanID: UInt64) -> Session? {
        state.withLock { state in
            guard state.sessionScanID == scanID, let session = state.session else { return nil }
            state.session = nil
            return session
        }
    }

    /// The scan with `scanID` was cancelled.
    /// - Pending: detach it like ``detach()`` and return its session and continuation.
    /// - Connecting: detach its session and mark it cancelled; the session is returned for
    ///   the caller to invalidate, and the connecting task fails the continuation (`nil` here).
    /// - Otherwise: remember the cancellation so ``begin(scanID:session:monitor:continuation:)``
    ///   refuses it, and return `nil`.
    func cancel(scanID: UInt64) -> (session: Session?, continuation: Continuation?)? {
        state.withLock { state in
            if let pending = state.pending, pending.scanID == scanID {
                let session = state.session
                state.session = nil
                state.pending = nil
                return (session, pending.continuation)
            }
            if var connecting = state.connecting, connecting.scanID == scanID, !connecting.cancelled {
                connecting.cancelled = true
                state.connecting = connecting
                if state.session === connecting.session {
                    state.session = nil
                }
                return (connecting.session, nil)
            }
            // Not begun yet (or already finished); record it so a later begin() refuses it.
            // The scan removes the marker with forgetCancellation(scanID:) when it ends.
            state.cancelledScanIDs.insert(scanID)
            return nil
        }
    }

    /// Forget a cancellation marker for a scan that ended without calling `begin`.
    func forgetCancellation(scanID: UInt64) {
        state.withLock { _ = $0.cancelledScanIDs.remove(scanID) }
    }
}
