import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCISO7816Tag`.
public final class ISO7816Transport: ISO7816TagTransporting, @unchecked Sendable {
    private let tag: NFCISO7816Tag
    /// Set by `NFCSessionManager`: once the user cancels the session, failures are
    /// reported as `NFCError.userCanceled`.
    private let terminationMonitor: SessionTerminationMonitor?

    public var identifier: Data {
        tag.identifier
    }

    public var initialAID: String {
        tag.initialSelectedAID
    }

    public init(tag: NFCISO7816Tag) {
        self.tag = tag
        terminationMonitor = nil
    }

    init(tag: NFCISO7816Tag, terminationMonitor: SessionTerminationMonitor?) {
        self.tag = tag
        self.terminationMonitor = terminationMonitor
    }

    public func send(_: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("Use sendAPDU for ISO 7816 tags")
    }

    public func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        NFCLog.debug("→ APDU \(apdu.bytes.hexDump)", source: "ISO7816")
        let nfcAPDU = NFCISO7816APDU(
            instructionClass: apdu.cla,
            instructionCode: apdu.ins,
            p1Parameter: apdu.p1,
            p2Parameter: apdu.p2,
            data: apdu.data ?? Data(),
            expectedResponseLength: apdu.nfcExpectedResponseLength
        )
        let (data, sw1, sw2) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.sendCommand(apdu: nfcAPDU)
        }
        NFCLog.debug("← SW:\(String(format: "%02X%02X", sw1, sw2)) \(data.hexDump)", source: "ISO7816")
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    /// Send an APDU and resolve `61xx` (GET RESPONSE) and `6Cxx` (wrong Le) statuses.
    /// The number of follow-up frames is bounded by ``APDUExchange``.
    public func sendAPDUWithChaining(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        try await APDUExchange.transmit(apdu) { try await self.sendAPDU($0) }
    }
}
