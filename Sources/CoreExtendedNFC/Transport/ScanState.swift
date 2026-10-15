import Foundation

/// Lock-protected bookkeeping for ``NFCSessionManager``: the current reader
/// session and the pending scan continuation.
///
/// Invariants:
/// - At most one scan is pending; a second ``begin(scanID:session:continuation:)`` is refused.
/// - A continuation is handed out at most once, so it is resumed exactly once.
/// - Callbacks from a session that is no longer current are ignored.
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

    private struct State {
        var session: Session?
        var pending: Pending?
        var nextScanID: UInt64 = 1
        var cancelledScanIDs: Set<UInt64> = []
    }

    private let state = LockedValue(State())

    /// Reserve an identifier for a scan before it starts, so cancellation that
    /// races ahead of ``begin(scanID:session:continuation:)`` is still observed.
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

    func begin(scanID: UInt64, session: Session, continuation: Continuation) -> BeginResult {
        state.withLock { state in
            if state.cancelledScanIDs.remove(scanID) != nil {
                return .cancelled
            }
            guard state.pending == nil else { return .busy }
            let replaced = state.session === session ? nil : state.session
            state.session = session
            state.pending = Pending(scanID: scanID, continuation: continuation)
            return .started(replacedSession: replaced)
        }
    }

    /// Whether `session` is the manager's current session.
    func isCurrent(_ session: Session) -> Bool {
        state.withLock { $0.session === session }
    }

    /// A tag was detected by `session`. Returns the continuation to resume, or `nil`
    /// if the session is stale or no scan is pending.
    func takeContinuationForDetection(by session: Session) -> Continuation? {
        state.withLock { state in
            guard state.session === session, let pending = state.pending else { return nil }
            state.pending = nil
            return pending.continuation
        }
    }

    /// `session` was invalidated by the system. Returns the pending continuation to fail,
    /// or `nil` for a stale session (one that is no longer current).
    func sessionInvalidated(_ session: Session) -> Continuation? {
        state.withLock { state in
            guard state.session === session else { return nil }
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

    /// The scan with `scanID` was cancelled. If it is pending, detach it like ``detach()``;
    /// otherwise remember the cancellation so ``begin(scanID:session:continuation:)``
    /// refuses it, and return `nil`.
    func cancel(scanID: UInt64) -> (session: Session?, continuation: Continuation)? {
        state.withLock { state in
            if let pending = state.pending, pending.scanID == scanID {
                let session = state.session
                state.session = nil
                state.pending = nil
                return (session, pending.continuation)
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
