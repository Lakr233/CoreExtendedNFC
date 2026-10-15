// Session lifecycle and CoreNFC error mapping tests.
//
// ## References
// - CoreNFC `NFCError.h`: `NFCReaderError` codes (100 transceive, 200 session invalidation)
// - CoreNFC `NFCISO15693Tag.h`: `NFCISO15693SystemInfo` reports absent fields as -1
// - ISO/IEC 15693-3 §10.4.12: Get System Information optional fields (Info flags b1–b4)
@testable import CoreExtendedNFC
import Foundation
import Testing

private final class FakeSession: Sendable {}

struct NFCSessionManagerTests {
    // MARK: - ScanState

    @Test
    func `stale session invalidation does not fail the next scan`() async throws {
        let state = ScanState<FakeSession, Int>()
        let oldSession = FakeSession()
        let newSession = FakeSession()

        let first = try await withCheckedThrowingContinuation { continuation in
            guard case .started = state.begin(scanID: state.makeScanID(), session: oldSession, continuation: continuation) else {
                continuation.resume(returning: -1)
                return
            }
            state.takeContinuationForDetection(by: oldSession)?.resume(returning: 1)
        }
        #expect(first == 1)

        // Caller invalidates, then immediately scans again.
        let detached = state.detach()
        #expect(detached.session === oldSession)
        #expect(detached.continuation == nil)

        let second = try await withCheckedThrowingContinuation { continuation in
            _ = state.begin(scanID: state.makeScanID(), session: newSession, continuation: continuation)
            // The old session's didInvalidate arrives late; it must be ignored.
            #expect(state.sessionInvalidated(oldSession) == nil)
            #expect(state.takeContinuationForDetection(by: oldSession) == nil)
            #expect(state.isCurrent(newSession))
            state.takeContinuationForDetection(by: newSession)?.resume(returning: 2)
        }
        #expect(second == 2)
        #expect(state.currentSession === newSession)
    }

    @Test
    func `second scan is refused while one is pending`() async throws {
        let state = ScanState<FakeSession, Int>()
        let firstSession = FakeSession()
        let secondSession = FakeSession()

        async let first: Int = withCheckedThrowingContinuation { continuation in
            _ = state.begin(scanID: state.makeScanID(), session: firstSession, continuation: continuation)
        }
        while !state.hasPendingScan {
            await Task.yield()
        }

        var secondWasBusy = false
        do {
            _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, any Error>) in
                if case .busy = state.begin(scanID: state.makeScanID(), session: secondSession, continuation: continuation) {
                    continuation.resume(throwing: NFCError.unsupportedOperation("busy"))
                } else {
                    continuation.resume(returning: -1)
                }
            }
        } catch {
            secondWasBusy = true
        }
        #expect(secondWasBusy)
        #expect(state.isCurrent(firstSession))

        state.takeContinuationForDetection(by: firstSession)?.resume(returning: 1)
        #expect(try await first == 1)
    }

    @Test
    func `cancellation before begin refuses the scan`() async {
        let state = ScanState<FakeSession, Int>()
        let scanID = state.makeScanID()
        #expect(state.cancel(scanID: scanID) == nil)

        var wasCancelled = false
        do {
            _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int, any Error>) in
                if case .cancelled = state.begin(scanID: scanID, session: FakeSession(), continuation: continuation) {
                    continuation.resume(throwing: CancellationError())
                } else {
                    continuation.resume(returning: 0)
                }
            }
        } catch is CancellationError {
            wasCancelled = true
        } catch {}
        #expect(wasCancelled)
        #expect(!state.hasPendingScan)
        #expect(state.currentSession == nil)
    }

    @Test
    func `cancelling a pending scan hands back session and continuation exactly once`() async {
        let state = ScanState<FakeSession, Int>()
        let session = FakeSession()
        let scanID = state.makeScanID()

        var thrownCancellation = false
        do {
            _ = try await withCheckedThrowingContinuation { continuation in
                _ = state.begin(scanID: scanID, session: session, continuation: continuation)
                guard let cancelled = state.cancel(scanID: scanID) else {
                    continuation.resume(returning: -1)
                    return
                }
                #expect(cancelled.session === session)
                // Late callbacks from the cancelled session find nothing to resume.
                #expect(state.sessionInvalidated(session) == nil)
                #expect(state.cancel(scanID: scanID) == nil)
                cancelled.continuation.resume(throwing: CancellationError())
            }
        } catch is CancellationError {
            thrownCancellation = true
        } catch {}
        #expect(thrownCancellation)
        #expect(state.currentSession == nil)
    }

    @Test
    func `system invalidation of the current session fails the pending scan`() async {
        let state = ScanState<FakeSession, Int>()
        let session = FakeSession()

        var failed = false
        do {
            _ = try await withCheckedThrowingContinuation { continuation in
                _ = state.begin(scanID: state.makeScanID(), session: session, continuation: continuation)
                state.sessionInvalidated(session)?.resume(throwing: NFCError.sessionTimeout)
            }
        } catch NFCError.sessionTimeout {
            failed = true
        } catch {}
        #expect(failed)
        #expect(state.currentSession == nil)
    }

    @Test
    func `a new scan supersedes a session left open by a completed scan`() async throws {
        let state = ScanState<FakeSession, Int>()
        let oldSession = FakeSession()
        let newSession = FakeSession()

        _ = try await withCheckedThrowingContinuation { continuation in
            _ = state.begin(scanID: state.makeScanID(), session: oldSession, continuation: continuation)
            state.takeContinuationForDetection(by: oldSession)?.resume(returning: 1)
        }

        var replaced: FakeSession?
        _ = try await withCheckedThrowingContinuation { continuation in
            if case let .started(previous) = state.begin(scanID: state.makeScanID(), session: newSession, continuation: continuation) {
                replaced = previous
            }
            state.takeContinuationForDetection(by: newSession)?.resume(returning: 2)
        }
        #expect(replaced === oldSession)
    }

    // MARK: - CoreNFC error mapping

    @Test
    func `NFCReaderError codes map to NFCError categories`() {
        // Codes from CoreNFC/NFCError.h.
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 100)) == "tagConnectionLost")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 101)) == "tagConnectionLost")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 104)) == "tagConnectionLost")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 103)) == "sessionInvalidated")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 200)) == "userCanceled")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 201)) == "sessionTimeout")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 203)) == "systemBusy")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 202)) == "sessionInvalidated")
        #expect(NFCReaderErrorMapping.map(code: 200)?.isUserCancellation == true)
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 1)) == "nfcNotAvailable")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 6)) == "nfcNotAvailable")
        #expect(Self.describe(NFCReaderErrorMapping.map(code: 105)) == "unsupportedOperation")
        #expect(NFCReaderErrorMapping.map(code: 400) == nil)

        if case let .invalidResponse(data) = NFCReaderErrorMapping.map(code: 102, iso15693ResponseCode: 0x12) {
            #expect(data == Data([0x12]))
        } else {
            Issue.record("Tag response error should map to invalidResponse")
        }
    }

    @Test
    func `error mapping leaves library and cancellation errors untouched`() {
        #expect(NFCReaderErrorMapping.map(NFCError.tagLocked) is NFCError)
        #expect(NFCReaderErrorMapping.map(CancellationError()) is CancellationError)

        let foreign = NSError(domain: "com.example.other", code: 100)
        #expect((NFCReaderErrorMapping.map(foreign) as NSError).domain == "com.example.other")
    }

    @Test
    func `unknown session invalidation errors still surface as NFCError`() {
        let error = NFCSessionManager.invalidationError(from: NSError(domain: "com.example.other", code: 7))
        guard case NFCError.sessionInvalidated = error else {
            Issue.record("Expected sessionInvalidated, got \(error)")
            return
        }
    }

    @Test
    func `session loss classification`() {
        #expect(isSessionTerminating(NFCError.tagConnectionLost))
        #expect(isSessionTerminating(NFCError.sessionTimeout))
        #expect(isSessionTerminating(NFCError.sessionInvalidated("x")))
        #expect(isSessionTerminating(CancellationError()))
        #expect(isSessionTerminating(NFCError.userCanceled))
        #expect(!isSessionTerminating(NFCError.felicaBlockReadFailed(statusFlag: 0xA1)))
        #expect(!isSessionTerminating(NFCError.invalidResponse(Data())))
    }

    // MARK: - ISO 15693 system info

    @Test
    func `ISO 15693 system info with absent optional fields does not trap`() {
        let info = ISO15693Transport.makeSystemInfo(
            uid: Data(repeating: 0xE0, count: 8),
            dsfid: -1,
            afi: -1,
            blockSize: -1,
            totalBlocks: -1,
            icReference: -1
        )
        #expect(info.dsfid == nil)
        #expect(info.afi == nil)
        #expect(info.icReference == nil)
        #expect(info.blockSize == -1)
        #expect(info.blockCount == -1)
    }

    @Test
    func `ISO 15693 system info keeps reported values`() {
        let info = ISO15693Transport.makeSystemInfo(
            uid: Data(repeating: 0xE0, count: 8),
            dsfid: 0x12,
            afi: 0x07,
            blockSize: 4,
            totalBlocks: 28,
            icReference: 0x01
        )
        #expect(info.dsfid == 0x12)
        #expect(info.afi == 0x07)
        #expect(info.icReference == 0x01)
        #expect(info.blockSize == 4)
        #expect(info.blockCount == 28)
    }

    private static func describe(_ error: NFCError?) -> String? {
        guard let error else { return nil }
        return switch error {
        case .tagConnectionLost: "tagConnectionLost"
        case .sessionInvalidated: "sessionInvalidated"
        case .sessionTimeout: "sessionTimeout"
        case .userCanceled: "userCanceled"
        case .systemBusy: "systemBusy"
        case .nfcNotAvailable: "nfcNotAvailable"
        case .unsupportedOperation: "unsupportedOperation"
        case .invalidResponse: "invalidResponse"
        default: "other"
        }
    }
}
