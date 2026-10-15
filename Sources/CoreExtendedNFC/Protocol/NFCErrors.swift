import Foundation

/// All errors thrown by CoreExtendedNFC operations.
public enum NFCError: Error, Sendable {
    // MARK: Transport

    case nfcNotAvailable
    /// The reader session hit the system time limit
    /// (CoreNFC `readerSessionInvalidationErrorSessionTimeout`).
    case sessionTimeout
    /// The tag left the field or stopped answering
    /// (CoreNFC `readerTransceiveErrorTagConnectionLost`).
    case tagConnectionLost
    case tagNotSupported
    /// The reader session ended for a reason without a dedicated case.
    /// The associated text is the system's description of the reason.
    case sessionInvalidated(String)
    /// The user dismissed the system NFC sheet
    /// (CoreNFC `readerSessionInvalidationErrorUserCanceled`).
    case userCanceled
    /// Another reader session holds the NFC hardware
    /// (CoreNFC `readerSessionInvalidationErrorSystemIsBusy`).
    case systemBusy

    // MARK: Protocol

    case crcMismatch
    case invalidResponse(Data)
    case unexpectedStatusWord(UInt8, UInt8)
    /// The card kept asking for more response frames (`61xx`, `91AF`, …)
    /// beyond the limit a single exchange is allowed.
    case responseChainTooLong(maxFrames: Int)

    // MARK: MIFARE

    case authenticationFailed
    case writeFailed(page: UInt8)
    case tagLocked

    // MARK: DESFire

    case desfireError(DESFireStatus)

    // MARK: FeliCa

    case felicaBlockReadFailed(statusFlag: Int)
    case felicaBlockWriteFailed(statusFlag: Int)

    // MARK: Passport

    case bacFailed(String)
    case secureMessagingError(String)
    case dataGroupNotAvailable(String)
    case dataGroupParseFailed(String)
    case cryptoError(String)

    // MARK: General

    case notOperableOnIOS(CardType)
    case unsupportedOperation(String)
}

public extension NFCError {
    /// `true` when the session ended because the user dismissed the NFC sheet.
    /// Callers usually stay silent in this case instead of showing an error.
    var isUserCancellation: Bool {
        if case .userCanceled = self { return true }
        return false
    }
}

extension NFCError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .nfcNotAvailable:
            String(localized: "NFC is not available on this device.", bundle: .module)
        case .sessionTimeout:
            String(localized: "The NFC session timed out.", bundle: .module)
        case .tagConnectionLost:
            String(localized: "The connection to the tag was lost. Hold the tag still and try again.", bundle: .module)
        case .tagNotSupported:
            String(localized: "This tag is not supported.", bundle: .module)
        case let .sessionInvalidated(reason):
            String(localized: "The NFC session ended: \(reason)", bundle: .module)
        case .userCanceled:
            String(localized: "The NFC session was canceled.", bundle: .module)
        case .systemBusy:
            String(localized: "NFC is busy with another session. Try again.", bundle: .module)
        case .crcMismatch:
            String(localized: "The tag response failed its CRC check.", bundle: .module)
        case let .invalidResponse(data):
            String(localized: "The tag sent an invalid response (\(data.count) bytes).", bundle: .module)
        case let .unexpectedStatusWord(sw1, sw2):
            String(localized: "The card returned status \(Self.hexByte(sw1))\(Self.hexByte(sw2)).", bundle: .module)
        case let .responseChainTooLong(maxFrames):
            String(localized: "The card kept sending response frames past the limit of \(maxFrames).", bundle: .module)
        case .authenticationFailed:
            String(localized: "Authentication with the tag failed.", bundle: .module)
        case let .writeFailed(page):
            String(localized: "Writing page \(Int(page)) failed.", bundle: .module)
        case .tagLocked:
            String(localized: "The tag is locked.", bundle: .module)
        case let .desfireError(status):
            String(localized: "DESFire error: \(status.description).", bundle: .module)
        case let .felicaBlockReadFailed(statusFlag):
            String(localized: "FeliCa block read failed (status \(Self.hexStatus(statusFlag))).", bundle: .module)
        case let .felicaBlockWriteFailed(statusFlag):
            String(localized: "FeliCa block write failed (status \(Self.hexStatus(statusFlag))).", bundle: .module)
        case let .bacFailed(reason):
            String(localized: "Basic Access Control failed: \(reason)", bundle: .module)
        case let .secureMessagingError(reason):
            String(localized: "Secure messaging failed: \(reason)", bundle: .module)
        case let .dataGroupNotAvailable(name):
            String(localized: "Data group not available: \(name)", bundle: .module)
        case let .dataGroupParseFailed(reason):
            String(localized: "Could not parse card data: \(reason)", bundle: .module)
        case let .cryptoError(reason):
            String(localized: "Cryptographic operation failed: \(reason)", bundle: .module)
        case let .notOperableOnIOS(cardType):
            String(localized: "\(cardType.description) cards cannot be read on iOS.", bundle: .module)
        case let .unsupportedOperation(reason):
            String(localized: "Unsupported operation: \(reason)", bundle: .module)
        }
    }

    private static func hexByte(_ value: UInt8) -> String {
        String(format: "%02X", value)
    }

    private static func hexStatus(_ value: Int) -> String {
        String(format: "%02X", value)
    }
}
