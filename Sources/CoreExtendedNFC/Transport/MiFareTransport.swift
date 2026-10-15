import CoreNFC
import Foundation

/// Transport adapter wrapping `NFCMiFareTag`.
public final class MiFareTransport: NFCTagTransport, @unchecked Sendable {
    private let tag: NFCMiFareTag

    public var identifier: Data {
        tag.identifier
    }

    public var mifareFamily: NFCMiFareFamily {
        tag.mifareFamily
    }

    public init(tag: NFCMiFareTag) {
        self.tag = tag
    }

    public func send(_ data: Data) async throws -> Data {
        NFCLog.debug("→ SEND \(data.hexDump)", source: "MiFare")
        let response = try await withNFCErrorMapping {
            try await tag.sendMiFareCommand(commandPacket: data)
        }
        NFCLog.debug("← RECV \(response.hexDump)", source: "MiFare")
        return response
    }

    public func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        NFCLog.debug("→ APDU \(apdu.bytes.hexDump)", source: "MiFare")
        let nfcAPDU = NFCISO7816APDU(
            instructionClass: apdu.cla,
            instructionCode: apdu.ins,
            p1Parameter: apdu.p1,
            p2Parameter: apdu.p2,
            data: apdu.data ?? Data(),
            expectedResponseLength: apdu.nfcExpectedResponseLength
        )
        let (data, sw1, sw2) = try await withNFCErrorMapping {
            try await tag.sendMiFareISO7816Command(nfcAPDU)
        }
        NFCLog.debug("← SW:\(String(format: "%02X%02X", sw1, sw2)) \(data.hexDump)", source: "MiFare")
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }
}
