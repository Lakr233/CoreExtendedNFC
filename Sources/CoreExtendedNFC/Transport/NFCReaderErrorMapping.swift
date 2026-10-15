import CoreNFC
import Foundation

/// Translates CoreNFC `NFCReaderError` values into ``NFCError`` so callers can
/// tell a lost tag or an ended session from a card-level failure without
/// importing CoreNFC.
///
/// Raw codes come from `CoreNFC/NFCError.h` (`NFCReaderError`).
enum NFCReaderErrorMapping {
    /// Map any error thrown by CoreNFC. Errors from other domains pass through unchanged.
    static func map(_ error: any Error) -> any Error {
        if error is NFCError || error is CancellationError {
            return error
        }
        let nsError = error as NSError
        guard nsError.domain == NFCErrorDomain else { return error }
        let iso15693Code = (nsError.userInfo[NFCISO15693TagResponseErrorKey] as? NSNumber)?.intValue
        return map(code: nsError.code, iso15693ResponseCode: iso15693Code, description: nsError.localizedDescription)
            ?? error
    }

    /// Map a raw `NFCReaderError` code. Returns `nil` for codes this library does not classify.
    static func map(code: Int, iso15693ResponseCode: Int? = nil, description: String = "") -> NFCError? {
        switch code {
        // NFCReaderErrorUnsupportedFeature, NFCReaderErrorRadioDisabled,
        // NFCReaderErrorIneligible
        case 1, 6, 7:
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
            if let iso15693ResponseCode, let byte = UInt8(exactly: iso15693ResponseCode) {
                return .invalidResponse(Data([byte]))
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
        case .sessionInvalidated, .sessionTimeout, .tagConnectionLost, .nfcNotAvailable, .userCanceled, .systemBusy:
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

/// Run a CoreNFC call and rethrow its error as ``NFCError`` where a mapping exists.
func withNFCErrorMapping<T>(_ body: () async throws -> T) async throws -> T {
    do {
        return try await body()
    } catch {
        throw NFCReaderErrorMapping.map(error)
    }
}
