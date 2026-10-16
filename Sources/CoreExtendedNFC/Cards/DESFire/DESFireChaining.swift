import Foundation

public extension DESFireCommands {
    /// Upper bound on Additional Frame (91 AF) round trips for one command.
    ///
    /// The largest DESFire data files (8 KB) need about 140 frames of 59 bytes,
    /// so 1024 frames leaves ample headroom while still stopping a card or relay
    /// that answers 91 AF forever.
    static let maxAdditionalFrames = 1024

    /// Send command and collect all AF (Additional Frame) responses into a single buffer.
    func sendWithChaining(_ cmd: UInt8, data: Data?) async throws -> Data {
        NFCLog.desfireCommand(cmd, data: data, source: "DESFire")
        let apdu = CommandAPDU.desfireWrap(command: cmd, data: data)
        var response = try await transport.sendAPDU(apdu)
        var result = response.data

        // Keep sending AF frames while the card indicates more data
        var afCount = 0
        while response.hasMoreFrames {
            guard afCount < Self.maxAdditionalFrames else {
                NFCLog.error("DESFire AF chaining exceeded \(Self.maxAdditionalFrames) frames", source: "DESFire")
                throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
            }
            try Task.checkCancellation()
            afCount += 1
            let afAPDU = CommandAPDU.desfireWrap(command: Self.ADDITIONAL_FRAME)
            response = try await transport.sendAPDU(afAPDU)
            result.append(response.data)
        }

        if afCount > 0 {
            NFCLog.debug("DESFire AF chaining: \(afCount) frame(s), total \(result.count) bytes", source: "DESFire")
        }

        // Check final status. Only SW1 = 0x91 carries a DESFire native status
        // code; any other class (ISO 7816-4 6D00, 6E00, 6A82, ...) is reported as-is.
        guard response.sw1 == 0x91, response.sw2 == 0x00 else {
            if response.sw1 == 0x91, let status = DESFireStatus(rawValue: response.sw2) {
                NFCLog.error("DESFire error: \(status)", source: "DESFire")
                throw NFCError.desfireError(status)
            }
            throw NFCError.unexpectedStatusWord(response.sw1, response.sw2)
        }

        return result
    }
}
