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
    ///
    /// - Warning: Several Type 2 pages hold one-way bits or access settings, and a
    ///   write to them can permanently brick the tag or lock out the owner
    ///   (MF0ICU1/MF0ICU2/MF0ULx1/NTAG21x datasheets, "Memory organization"):
    ///   - page 2 bytes 2-3: static lock bytes (set bits can never be cleared);
    ///   - page 3: OTP / Capability Container (bits are OR-ed and never cleared);
    ///   - dynamic lock bytes, CFG0/CFG1 (MIRROR, AUTH0, ACCESS with PROT,
    ///     CFGLCK, AUTHLIM), PWD and PACK, and the Ultralight C AUTH0/AUTH1 and
    ///     3DES key pages.
    ///
    ///   Such writes are refused with ``NFCError/unsupportedOperation(_:)``
    ///   unless `allowIrreversible` is `true`. Pages 0-3 are always checked. The
    ///   configuration pages depend on the product, so pass `memoryMap`
    ///   (``UltralightMemoryMap/forType(_:)``) to also refuse every page outside
    ///   the product's user data area; without it only pages 0-3 are checked.
    ///   Page 3 is accepted without opt-in only for a standard read/write NDEF
    ///   Capability Container (`E1 1x xx 00`, NFC Forum T2T 1.0 §6.1), which is
    ///   what NDEF formatting writes; a read-only CC (CC3 ≠ 00h) or any other
    ///   OTP value needs the opt-in.
    ///
    /// - Parameters:
    ///   - page: Page address.
    ///   - data: Exactly 4 bytes.
    ///   - memoryMap: The tag's memory map, used to recognise lock and
    ///     configuration pages. `nil` checks only pages 0-3.
    ///   - allowIrreversible: Explicit opt-in to write lock, OTP and
    ///     configuration pages.
    public func writePage(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false
    ) async throws {
        guard data.count == 4 else {
            throw NFCError.unsupportedOperation("Write data must be exactly 4 bytes")
        }
        try Self.requireWritable(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
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
    ///
    /// - Warning: Lock, OTP and configuration pages are refused unless
    ///   `allowIrreversible` is `true`, exactly as for
    ///   ``writePage(_:data:memoryMap:allowIrreversible:)``.
    public func compatibilityWrite(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false
    ) async throws {
        guard data.count == 4 else {
            throw NFCError.unsupportedOperation("Write data must be exactly 4 bytes")
        }
        try Self.requireWritable(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
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
    /// this does not leave the tag mid-authentication.
    ///
    /// ## NAK recovery assumption
    /// Per the MF0ICU1/MF0ICU2 datasheets a NAK sends the tag back to IDLE.
    /// Like every other Ultralight path in this library (GET_VERSION on
    /// MF0ICU1/2, READ past AUTH0 during a dump), this probe assumes CoreNFC
    /// re-activates the tag before the next command, so the tag is still
    /// usable after a NAK. That re-activation is an on-device verification
    /// item; the unit-test tag models apply the same rule to every NAK.
    ///
    /// - Throws: Session loss and task cancellation (``NFCError/sessionInvalidated(_:)``,
    ///   ``NFCError/userCanceled``, `CancellationError`, ...). A missing answer
    ///   (``NFCError/tagConnectionLost``) is treated as "not Ultralight C",
    ///   because CoreNFC reports a NAKed or unanswered optional command the same
    ///   way; the next mandatory command fails if the tag really left the field.
    public func probeUltralightCMemory() async throws -> Bool {
        let response: Data
        do {
            response = try await transport.send(Data([0x30, 0x2B]))
        } catch where isSessionTerminating(error) && !isMissingTagResponse(error) {
            throw error
        } catch {
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

    /// Refuse a write to a lock, OTP or configuration page unless the caller opted in.
    static func requireWritable(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap?,
        allowIrreversible: Bool
    ) throws {
        guard !allowIrreversible else { return }
        let reason: String? = switch page {
        case 0x00, 0x01:
            "page \(page) holds the UID"
        case 0x02:
            "page 2 holds the static lock bytes"
        case 0x03 where !isReadWriteNDEFCapabilityContainer(data):
            "page 3 is one-time programmable (OTP / Capability Container)"
        case 0x03:
            nil
        default:
            if let memoryMap, !memoryMap.isUserDataPage(page) {
                "page \(page) is a lock, configuration, password or key page"
            } else {
                nil
            }
        }
        if let reason {
            throw NFCError.unsupportedOperation(
                "Refusing to write: \(reason) and the change may be irreversible. Pass allowIrreversible: true to write it anyway."
            )
        }
    }

    /// A standard NFC Forum Type 2 CC granting read and write access:
    /// CC0 = E1h (NDEF magic), CC1 major version 1, CC3 = 00h (T2T 1.0 §6.1).
    private static func isReadWriteNDEFCapabilityContainer(_ data: Data) -> Bool {
        let bytes = [UInt8](data)
        return bytes.count == 4 && bytes[0] == 0xE1 && bytes[1] >> 4 == 0x1 && bytes[3] == 0x00
    }

    private static func requireACK(_ response: Data, page: UInt8) throws {
        if let firstByte = response.first, firstByte != 0x0A {
            throw NFCError.writeFailed(page: page)
        }
    }
}
