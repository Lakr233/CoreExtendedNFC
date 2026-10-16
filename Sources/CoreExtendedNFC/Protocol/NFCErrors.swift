import Foundation

/// All errors thrown by CoreExtendedNFC operations.
///
/// Match on the cases rather than on ``errorDescription`` text: the descriptions
/// are localized and may change. Cases that carry a `String` keep it for logs and
/// display only.
///
/// Write failures are reported per tag family: ``writeFailed(page:)`` for a Type 2
/// page write the tag did not acknowledge, ``felicaBlockWriteFailed(statusFlag:)``
/// for FeliCa, and ``iso15693Error(code:)`` (or ``tagLocked``) for ISO 15693 blocks.
public enum NFCError: Error, Sendable, Equatable {
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
    /// The app ended a pending scan itself with ``NFCSessionManager/invalidate()``
    /// or ``NFCSessionManager/invalidate(errorMessage:)``.
    case sessionInvalidatedByCaller
    /// ``NFCSessionManager/scan(for:message:)`` was called while another scan on the
    /// same manager was still waiting for a tag.
    case scanInProgress

    // MARK: Protocol

    case crcMismatch
    /// A checksum carried in the card's data (not the RF frame CRC) did not match,
    /// for example the FeliCa Type 3 attribute information block checksum.
    case checksumMismatch
    case invalidResponse(Data)
    case unexpectedStatusWord(UInt8, UInt8)
    /// The card kept asking for more response frames (`61xx`, `91AF`, …)
    /// beyond the limit a single exchange is allowed.
    case responseChainTooLong(maxFrames: Int)
    /// SELECT by AID was answered with "file or application not found"
    /// (`6A82`, `6A86`, `6999`, …): the card does not carry that application.
    case applicationNotFound(aid: Data)
    /// An ISO 15693 tag answered a command with an error flag and this ISO/IEC 15693-3
    /// error code (for example `0x0F` unknown error, `0x10` block not available,
    /// `0x13` block not programmed). Codes `0x12` / `0x14` (block locked) are reported
    /// as ``tagLocked`` instead.
    case iso15693Error(code: UInt8)

    // MARK: MIFARE

    case authenticationFailed
    /// ISO/IEC 7816-4 VERIFY was refused, or the PIN is blocked.
    /// `remainingAttempts` is the retry counter from `63Cx`, `0` when the PIN
    /// is blocked (`63C0`, `6983`, `6984`), and `nil` when the card did not say.
    case pinVerificationFailed(remainingAttempts: Int?)
    /// The operation needs this PIN, but none was supplied.
    case pinRequired(MyNumberPINType)
    case writeFailed(page: UInt8)
    case tagLocked
    /// The write would change a one-time-programmable or lock page irreversibly
    /// (lock bits, OTP, configuration lock) and was refused before anything was sent.
    case irreversibleWriteRefused(page: UInt8)

    // MARK: NDEF

    /// The tag has no NDEF Capability Container (or NDEF application), so it has to be
    /// formatted before an NDEF message can be read from or written to it.
    case tagNotNDEFFormatted
    /// The tag is NDEF formatted but holds no readable NDEF message TLV.
    case ndefMessageNotFound
    /// The encoded NDEF message (`required` bytes, including any TLV or length header)
    /// does not fit the `capacity` bytes the tag's NDEF area offers.
    case ndefCapacityExceeded(required: Int, capacity: Int)

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

    /// iOS cannot operate this card type at all (for example MIFARE Classic, whose
    /// Crypto1 authentication CoreNFC cannot carry). Unlike ``tagNotSupported`` this
    /// names the identified card type.
    case notOperableOnIOS(CardType)
    /// The requested operation does not apply to this transport or card (for example
    /// a FeliCa command on an ISO 7816 transport), or a command the reader refused.
    case unsupportedOperation(String)
    /// An argument passed to the API is out of range or malformed.
    case invalidParameter(String)
    /// A memory dump being exported or imported is malformed or inconsistent.
    case malformedDump(String)
}

public extension NFCError {
    /// `true` when the session ended because the user dismissed the NFC sheet.
    /// Callers usually stay silent in this case instead of showing an error.
    var isUserCancellation: Bool {
        if case .userCanceled = self { return true }
        return false
    }
}

public extension Error {
    /// `true` when the NFC operation ended because it was cancelled rather than
    /// because it failed: the user dismissed the NFC sheet (``NFCError/userCanceled``),
    /// the calling task was cancelled (`CancellationError`), or the app ended a pending
    /// scan itself (``NFCError/sessionInvalidatedByCaller``).
    ///
    /// Apps usually stay silent in these cases instead of showing an error.
    var isNFCCancellation: Bool {
        if self is CancellationError { return true }
        switch self as? NFCError {
        case .userCanceled?, .sessionInvalidatedByCaller?:
            return true
        default:
            return false
        }
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
        case .sessionInvalidatedByCaller:
            String(localized: "The NFC session was ended by the app.", bundle: .module)
        case .scanInProgress:
            String(localized: "An NFC scan is already in progress.", bundle: .module)
        case .crcMismatch:
            String(localized: "The tag response failed its CRC check.", bundle: .module)
        case .checksumMismatch:
            String(localized: "The card data failed its checksum.", bundle: .module)
        case let .invalidResponse(data):
            String(localized: "The tag sent an invalid response (\(data.count) bytes).", bundle: .module)
        case let .unexpectedStatusWord(sw1, sw2):
            String(localized: "The card returned status word \(Self.hexByte(sw1))\(Self.hexByte(sw2)).", bundle: .module)
        case let .responseChainTooLong(maxFrames):
            String(localized: "The card kept sending response frames past the limit of \(maxFrames).", bundle: .module)
        case let .applicationNotFound(aid):
            String(localized: "The card does not have application \(aid.map { Self.hexByte($0) }.joined()).", bundle: .module)
        case let .iso15693Error(code):
            String(localized: "The tag reported ISO 15693 error \(Self.hexByte(code)).", bundle: .module)
        case .authenticationFailed:
            String(localized: "Authentication with the tag failed.", bundle: .module)
        case let .pinVerificationFailed(remainingAttempts):
            switch remainingAttempts {
            case .none:
                String(localized: "PIN verification failed.", bundle: .module)
            case 0:
                String(localized: "The PIN is blocked. No attempts remain.", bundle: .module)
            case let .some(count):
                String(localized: "PIN verification failed. \(count) attempt(s) remaining.", bundle: .module)
            }
        case let .pinRequired(pinType):
            String(localized: "A PIN is required: \(Self.pinName(pinType)).", bundle: .module)
        case let .writeFailed(page):
            String(localized: "Writing page \(Int(page)) failed.", bundle: .module)
        case .tagLocked:
            String(localized: "The tag is locked.", bundle: .module)
        case let .irreversibleWriteRefused(page):
            String(localized: "Writing page \(Int(page)) would permanently change the tag, so it was refused.", bundle: .module)
        case .tagNotNDEFFormatted:
            String(localized: "The tag is not NDEF formatted. Format it first.", bundle: .module)
        case .ndefMessageNotFound:
            String(localized: "No NDEF message was found on the tag.", bundle: .module)
        case let .ndefCapacityExceeded(required, capacity):
            String(localized: "The NDEF message needs \(required) bytes, but the tag holds only \(capacity).", bundle: .module)
        case let .desfireError(status):
            String(localized: "DESFire error: \(status.description).", bundle: .module)
        case let .felicaBlockReadFailed(statusFlag):
            String(localized: "FeliCa block read failed (status flags \(Self.hexStatus(statusFlag))).", bundle: .module)
        case let .felicaBlockWriteFailed(statusFlag):
            String(localized: "FeliCa block write failed (status flags \(Self.hexStatus(statusFlag))).", bundle: .module)
        case let .bacFailed(reason):
            String(localized: "Basic Access Control failed: \(reason)", bundle: .module)
        case let .secureMessagingError(reason):
            String(localized: "Secure Messaging failed: \(reason)", bundle: .module)
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
        case let .invalidParameter(reason):
            String(localized: "Invalid parameter: \(reason)", bundle: .module)
        case let .malformedDump(reason):
            String(localized: "The dump is malformed: \(reason)", bundle: .module)
        }
    }

    public static func hexByte(_ value: UInt8) -> String {
        String(format: "%02X", value)
    }

    public static func pinName(_ pinType: MyNumberPINType) -> String {
        switch pinType {
        case .digitalSignature:
            String(localized: "digital signature PIN", bundle: .module)
        case .userAuthentication:
            String(localized: "user authentication PIN", bundle: .module)
        case .cardInfoInputSupport:
            String(localized: "card info input support PIN", bundle: .module)
        case .individualNumber:
            String(localized: "individual number PIN", bundle: .module)
        }
    }

    public static func hexStatus(_ value: Int) -> String {
        String(format: "%02X", value)
    }
}
