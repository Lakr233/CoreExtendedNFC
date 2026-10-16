import CoreNFC
import Foundation

/// Translates CoreNFC `NFCReaderError` values into ``NFCError`` so callers can
/// tell a lost tag or an ended session from a card-level failure without
/// importing CoreNFC.
///
/// Raw codes come from `CoreNFC/NFCError.h` (`NFCReaderError`).
enum NFCReaderErrorMapping {
    /// Where the error was reported. Some codes mean different things for a single
    /// tag command than for the end of the whole session.
    enum Context {
        /// A tag command (transceive) failed.
        case command
        /// `tagReaderSession(_:didInvalidateWithError:)` ended the session.
        case sessionInvalidation
    }

    /// Map any error thrown by CoreNFC. Errors from other domains pass through unchanged.
    ///
    /// - Parameter userCanceledSession: the user already dismissed this session; a
    ///   session-loss failure is then reported as ``NFCError/userCanceled``.
    static func map(
        _ error: any Error,
        context: Context = .command,
        userCanceledSession: Bool = false
    ) -> any Error {
        if error is NFCError || error is CancellationError {
            return error
        }
        let nsError = error as NSError
        guard nsError.domain == NFCErrorDomain else { return error }
        let iso15693Code = (nsError.userInfo[NFCISO15693TagResponseErrorKey] as? NSNumber)?.intValue
        return map(
            code: nsError.code,
            iso15693ResponseCode: iso15693Code,
            description: nsError.localizedDescription,
            context: context,
            userCanceledSession: userCanceledSession
        ) ?? error
    }

    /// Map a raw `NFCReaderError` code. Returns `nil` for codes this library does not classify.
    static func map(
        code: Int,
        iso15693ResponseCode: Int? = nil,
        description: String = "",
        context: Context = .command,
        userCanceledSession: Bool = false
    ) -> NFCError? {
        let mapped = mapCode(code, iso15693ResponseCode: iso15693ResponseCode, description: description, context: context)
        // After the user dismissed the sheet, the in-flight and later commands fail with
        // session or connection errors (103, 104, ...); the real cause is the user cancel.
        if userCanceledSession, let mapped, mapped.isSessionLoss {
            return .userCanceled
        }
        return mapped
    }

    private static func mapCode(
        _ code: Int,
        iso15693ResponseCode: Int?,
        description: String,
        context: Context
    ) -> NFCError? {
        switch code {
        // NFCReaderErrorUnsupportedFeature. As a session invalidation it means the device
        // cannot read tags; for one command it means that command or tag feature is
        // unsupported, which must not end a best-effort read or suggest NFC is off.
        case 1:
            switch context {
            case .command:
                return .unsupportedOperation(Self.detail("The tag or reader does not support this command", description))
            case .sessionInvalidation:
                return .nfcNotAvailable
            }
        // NFCReaderErrorRadioDisabled, NFCReaderErrorIneligible
        case 6, 7:
            return .nfcNotAvailable
        // NFCReaderErrorSecurityViolation, AccessNotAccepted
        case 2, 8:
            return .unsupportedOperation(Self.detail("NFC access was not granted", description))
        // NFCReaderErrorInvalidParameter / InvalidParameterLength / ParameterOutOfBound,
        // NFCTagCommandConfigurationErrorInvalidParameters
        case 3, 4, 5, 300:
            return .unsupportedOperation(Self.detail("Invalid NFC command parameters", description))
        // NFCReaderTransceiveErrorTagConnectionLost, RetryExceeded, TagNotConnected
        case 100, 101, 104:
            return .tagConnectionLost
        // NFCReaderTransceiveErrorTagResponseError: the tag answered with an error.
        case 102:
            // ISO 15693 tags report an ISO/IEC 15693-3 §7.4 error code with the response.
            if let iso15693ResponseCode, let byte = UInt8(exactly: iso15693ResponseCode) {
                switch byte {
                // 0x12: block already locked, cannot change content.
                // 0x14: block could not be locked (already locked or lock failed).
                case 0x12, 0x14:
                    return .tagLocked
                default:
                    return .iso15693Error(code: byte)
                }
            }
            return .invalidResponse(Data())
        // NFCReaderTransceiveErrorSessionInvalidated
        case 103:
            return .sessionInvalidated(Self.detail("Session invalidated", description))
        // NFCReaderTransceiveErrorPacketTooLong
        case 105:
            return .unsupportedOperation(Self.detail("Command packet too long", description))
        // NFCReaderSessionInvalidationErrorUserCanceled
        case 200:
            return .userCanceled
        // NFCReaderSessionInvalidationErrorSessionTimeout
        case 201:
            return .sessionTimeout
        // NFCReaderSessionInvalidationErrorSystemIsBusy
        case 203:
            return .systemBusy
        // SessionTerminatedUnexpectedly, FirstNDEFTagRead
        case 202, 204:
            return .sessionInvalidated(Self.detail("Session ended", description))
        default:
            return nil
        }
    }

    private static func detail(_ fallback: String, _ description: String) -> String {
        description.isEmpty ? fallback : description
    }
}

extension NFCError {
    /// Whether this error means the RF session or tag link is gone, so further
    /// commands in the same session cannot succeed.
    var isSessionLoss: Bool {
        switch self {
        case .sessionInvalidated, .sessionInvalidatedByCaller, .sessionTimeout, .tagConnectionLost, .nfcNotAvailable,
             .userCanceled, .systemBusy:
            true
        default:
            false
        }
    }
}

/// Whether `error` ends the current read flow (session loss or task cancellation)
/// rather than describing a single unreadable item on the card.
func isSessionTerminating(_ error: any Error) -> Bool {
    if error is CancellationError { return true }
    if let nfcError = error as? NFCError { return nfcError.isSessionLoss }
    return false
}

/// Whether `error` is the "no answer from the tag" failure (CoreNFC 100/101/104).
///
/// CoreNFC reports a tag that left the field and a tag that stayed silent on a
/// command it does not implement with the same codes, so after an *optional*
/// command this is not proof that the tag is gone. Callers that tolerate it must
/// follow up with a mandatory command, which fails if the tag really is gone.
func isMissingTagResponse(_ error: any Error) -> Bool {
    if case NFCError.tagConnectionLost = error { return true }
    return false
}

/// Run a CoreNFC call and rethrow its error as ``NFCError`` where a mapping exists.
///
/// - Parameter monitor: the session's termination record; once the user has
///   cancelled the session, session-loss failures become ``NFCError/userCanceled``.
func withNFCErrorMapping<T>(
    _ monitor: SessionTerminationMonitor? = nil,
    _ body: () async throws -> T
) async throws -> T {
    do {
        return try await body()
    } catch {
        throw NFCReaderErrorMapping.map(error, userCanceledSession: monitor?.userCanceled ?? false)
    }
}
