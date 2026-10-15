import Foundation

/// MIFARE Ultralight / NTAG command builder and sender.
/// Ported from libnfc utils/nfc-mfultralight.c and utils/mifare.h.
public struct UltralightCommands: Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    /// READ (0x30): Read 4 pages (16 bytes) starting at `startPage`.
    public func readPages(startPage: UInt8) async throws -> Data {
        let response = try await transport.send(Data([0x30, startPage]))
        guard response.count >= 16 else {
            throw NFCError.invalidResponse(response)
        }
        return response
    }

    /// WRITE (0xA2): Write 4 bytes to a single page.
    public func writePage(_ page: UInt8, data: Data) async throws {
        guard data.count == 4 else {
            throw NFCError.unsupportedOperation("Write data must be exactly 4 bytes")
        }
        var command = Data([0xA2, page])
        command.append(data)
        let response = try await transport.send(command)
        // ACK is 0x0A (single byte)
        if let firstByte = response.first, firstByte != 0x0A {
            throw NFCError.writeFailed(page: page)
        }
    }

    /// FAST_READ (0x3A): Read a range of pages [start...end] inclusive.
    /// Returns (end - start + 1) × 4 bytes.
    public func fastRead(from start: UInt8, to end: UInt8) async throws -> Data {
        guard end >= start else {
            throw NFCError.unsupportedOperation("FAST_READ end page must not be before start page")
        }
        let expectedLength = (Int(end) - Int(start) + 1) * 4
        let response = try await transport.send(Data([0x3A, start, end]))
        guard response.count >= expectedLength else {
            throw NFCError.invalidResponse(response)
        }
        return Data(response.prefix(expectedLength))
    }

    /// COMPATIBILITY WRITE (0xA0): Write 4 bytes using the two-phase,
    /// MIFARE Classic-compatible frame sequence.
    ///
    /// Phase 1 sends `A0 Addr` and expects an ACK; phase 2 sends 16 data bytes
    /// (only the first 4 are written) and expects a second ACK
    /// (MF0ICU1 / MF0ULx1 / NTAG21x datasheets, COMPATIBILITY_WRITE).
    public func compatibilityWrite(_ page: UInt8, data: Data) async throws {
        guard data.count == 4 else {
            throw NFCError.unsupportedOperation("Write data must be exactly 4 bytes")
        }
        let addressResponse = try await transport.send(Data([0xA0, page]))
        try Self.requireACK(addressResponse, page: page)

        var payload = Data(data)
        payload.append(Data(repeating: 0x00, count: 12))
        let dataResponse = try await transport.send(payload)
        try Self.requireACK(dataResponse, page: page)
    }

    /// READ probe used to tell MIFARE Ultralight C apart from plain Ultralight
    /// without starting an authentication.
    ///
    /// - MF0ICU2 (Ultralight C) datasheet, "Memory organization": 48 pages,
    ///   page 0x2B is AUTH1, the last readable page before the 3DES key
    ///   pages 0x2C-0x2F. "READ" command: a valid address returns 16 bytes.
    /// - MF0ICU1 (Ultralight) datasheet, "READ" command: valid addresses are
    ///   0x00-0x0F; a larger address is answered with a NAK.
    ///
    /// So a 16-byte answer to `30 2B` means Ultralight C. A NAK means plain
    /// Ultralight, or an Ultralight C whose AUTH0/AUTH1 read-protect page 0x2B;
    /// that card keeps the generic Ultralight type, which is a safe
    /// under-identification. Unlike ``probeUltralightCAuthentication()``,
    /// this leaves the tag in its normal ACTIVE state.
    public func probeUltralightCMemory() async -> Bool {
        guard let response = try? await transport.send(Data([0x30, 0x2B])) else {
            return false
        }
        return response.count >= 16
    }

    /// AUTHENTICATE (0x1A) probe used to tell MIFARE Ultralight C apart from
    /// plain Ultralight (NXP AN10833 §3.2; MF0ICU2 datasheet).
    ///
    /// Ultralight C answers `1A 00` with `AF ‖ ek(RndB)` (9 bytes). Any other
    /// answer, or a transport error, means the tag is not an Ultralight C.
    ///
    /// - Important: The probe leaves the tag mid-authentication. Per the MF0ICU2
    ///   datasheet any next command other than the AF second step is NAKed
    ///   and drops the tag to IDLE, so the tag must be re-selected before use.
    ///   The library's own identification uses ``probeUltralightCMemory()``.
    public func probeUltralightCAuthentication() async -> Bool {
        guard let response = try? await transport.send(Data([0x1A, 0x00])) else {
            return false
        }
        return response.count == 9 && response.first == 0xAF
    }

    private static func requireACK(_ response: Data, page: UInt8) throws {
        if let firstByte = response.first, firstByte != 0x0A {
            throw NFCError.writeFailed(page: page)
        }
    }
}
