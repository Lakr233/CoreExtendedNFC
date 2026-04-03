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

    // Accessed from the NFC delegate queue and the scan continuation.
    private var continuation: CheckedContinuation<(CardInfo, any NFCTagTransport), Error>?
    private var session: NFCTagReaderSession?

    /// Scan for a tag and return the identified card plus transport.
    /// Call ``invalidate()`` when follow-up operations are finished.
    public func scan(
        for targets: [PollingTarget] = [.all],
        message: String? = nil
    ) async throws -> (CardInfo, any NFCTagTransport) {
        try await withCheckedThrowingContinuation { continuation in
            guard NFCTagReaderSession.readingAvailable else {
                continuation.resume(throwing: NFCError.nfcNotAvailable)
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
            self.continuation = continuation
            self.session = session
            session.alertMessage = message ?? String(localized: "Hold your iPhone near the NFC tag", bundle: .module)
            session.begin()
        }
    }

    /// Update the alert message shown on the NFC system UI.
    public func setAlertMessage(_ message: String) {
        session?.alertMessage = message
    }

    /// Invalidate the session with a success checkmark.
    public func invalidate() {
        session?.invalidate()
        session = nil
    }

    /// Invalidate the session showing an error message.
    public func invalidate(errorMessage: String) {
        session?.invalidate(errorMessage: errorMessage)
        session = nil
    }

    // MARK: - NFCTagReaderSessionDelegate

    public func tagReaderSessionDidBecomeActive(_: NFCTagReaderSession) {
        NFCLog.info("NFC session active, waiting for tag…", source: "Session")
    }

    public func tagReaderSession(_: NFCTagReaderSession, didInvalidateWithError error: Error) {
        session = nil
        NFCLog.info("Session invalidated: \(error.localizedDescription)", source: "Session")
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(throwing: NFCError.sessionInvalidated(error.localizedDescription))
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let detectedTag = tags.first else {
            NFCLog.debug("No tags in detection batch, restarting polling", source: "Session")
            session.restartPolling()
            return
        }
        guard let continuation else { return }
        self.continuation = nil

        nonisolated(unsafe) let readerSession = session
        nonisolated(unsafe) let nfcTag = detectedTag
        let cont = continuation
        Task { @Sendable in
            do {
                try await readerSession.connect(to: nfcTag)
                let (cardInfo, transport) = try Self.identifyTag(nfcTag)
                NFCLog.info("Tag detected: \(cardInfo.type.description) UID:\(cardInfo.uid.hexDump)", source: "Session")
                cont.resume(returning: (cardInfo, transport))
            } catch {
                NFCLog.error("Tag connection failed: \(error.localizedDescription)", source: "Session")
                readerSession.invalidate(errorMessage: error.localizedDescription)
                cont.resume(throwing: error)
            }
        }
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
