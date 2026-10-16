import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCMiFareTag`.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class MiFareTransport: NFCTagTransport, @unchecked Sendable {
    public let tag: NFCMiFareTag
    /// Set by `NFCSessionManager`: once the user cancels the session, failures are
    /// reported as `NFCError.userCanceled`.
    public let terminationMonitor: SessionTerminationMonitor?

    open var identifier: Data {
        tag.identifier
    }

    open var mifareFamily: NFCMiFareFamily {
        tag.mifareFamily
    }

    public init(tag: NFCMiFareTag, terminationMonitor: SessionTerminationMonitor? = nil) {
        self.tag = tag
        self.terminationMonitor = terminationMonitor
    }

    open func send(_ data: Data) async throws -> Data {
        NFCLog.rawCommand(data, family: .mifare, source: "MiFare")
        let response = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.sendMiFareCommand(commandPacket: data)
        }
        NFCLog.rawResponse(response, command: data, family: .mifare, source: "MiFare")
        return response
    }

    open func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        NFCLog.apduCommand(apdu, source: "MiFare")
        let nfcAPDU = NFCISO7816APDU(
            instructionClass: apdu.cla,
            instructionCode: apdu.ins,
            p1Parameter: apdu.p1,
            p2Parameter: apdu.p2,
            data: apdu.data ?? Data(),
            expectedResponseLength: apdu.nfcExpectedResponseLength
        )
        let (data, sw1, sw2) = try await withNFCErrorMapping(terminationMonitor) {
            try await tag.sendMiFareISO7816Command(nfcAPDU)
        }
        NFCLog.apduResponse(data: data, sw1: sw1, sw2: sw2, for: apdu, source: "MiFare")
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }
}
