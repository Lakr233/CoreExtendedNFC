import Foundation

/// MIFARE Ultralight / NTAG command builder and sender.
/// Ported from libnfc utils/nfc-mfultralight.c and utils/mifare.h.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class UltralightCommands: @unchecked Sendable {
    public let transport: any NFCTagTransport

    public init(transport: any NFCTagTransport) {
        self.transport = transport
    }

    /// READ (0x30): Read 4 pages (16 bytes) starting at `startPage`.
    open func readPages(startPage: UInt8) async throws -> Data {
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
    ///   Such writes are refused with ``NFCError/irreversibleWriteRefused(page:)``
    ///   unless `allowIrreversible` is `true`. Pages 0-3 are always checked. The
    ///   configuration pages depend on the product, so pass `memoryMap`
    ///   (``UltralightMemoryMap/forType(_:)``) to also refuse every page outside
    ///   the product's user data area; without it only pages 0-3 are checked.
    ///
    ///   Because page 3 bits are OR-ed into the current value, a page 3 write
    ///   without the opt-in first reads page 3 and is sent only when it would
    ///   not change anything (every bit of `data` is already set). Writing a new
    ///   Capability Container needs `allowIrreversible: true`, which is what
    ///   ``CoreExtendedNFC/formatNDEF(info:transport:)`` does.
    ///
    /// The tag must answer with the 4-bit ACK, which CoreNFC delivers as the
    /// single byte `0Ah`; an empty answer or a NAK throws
    /// ``NFCError/writeFailed(page:)``.
    ///
    /// - Parameters:
    ///   - page: Page address.
    ///   - data: Exactly 4 bytes.
    ///   - memoryMap: The tag's memory map, used to recognise lock and
    ///     configuration pages. `nil` checks only pages 0-3.
    ///   - allowIrreversible: Explicit opt-in to write lock, OTP and
    ///     configuration pages.
    /// - Throws: ``NFCError/invalidParameter(_:)`` when `data` is not 4 bytes.
    open func writePage(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false
    ) async throws {
        guard data.count == 4 else {
            throw NFCError.invalidParameter("Write data must be exactly 4 bytes")
        }
        try await requireWritable(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
        var command = Data([0xA2, page])
        command.append(data)
        let response = try await transport.send(command)
        try Self.requireACK(response, page: page)
    }

    /// FAST_READ (0x3A): Read a range of pages [start...end] inclusive.
    /// Returns (end - start + 1) × 4 bytes.
    open func fastRead(from start: UInt8, to end: UInt8) async throws -> Data {
        guard end >= start else {
            throw NFCError.invalidParameter("FAST_READ end page must not be before start page")
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
    ///   ``writePage(_:data:memoryMap:allowIrreversible:)``. Both phases must be
    ///   answered with the ACK byte `0Ah`.
    open func compatibilityWrite(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap? = nil,
        allowIrreversible: Bool = false
    ) async throws {
        guard data.count == 4 else {
            throw NFCError.invalidParameter("Write data must be exactly 4 bytes")
        }
        try await requireWritable(page, data: data, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
        let addressResponse = try await transport.send(Data([0xA0, page]))
        try Self.requireACK(addressResponse, page: page)

        var payload = Data(data)
        payload.append(Data(repeating: 0x00, count: 12))
        // The data frame has no command byte; keep a password or key out of the logs.
        let dataResponse = try await NFCLogRedaction.$redactRawFrames.withValue(
            NFCLogRedaction.redactRawFrames || NFCLogRedaction.isSecretMiFarePage(page)
        ) {
            try await transport.send(payload)
        }
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
    open func probeUltralightCMemory() async throws -> Bool {
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
    open func probeUltralightCAuthentication() async -> Bool {
        guard let response = try? await transport.send(Data([0x1A, 0x00])) else {
            return false
        }
        return response.count == 9 && response.first == 0xAF
    }

    /// Refuse a write to a lock, OTP or configuration page unless the caller opted in.
    ///
    /// Page 3 is OTP: the written bits are OR-ed into the current value. Without
    /// the opt-in it is read first and the write is allowed only when it would
    /// leave the page unchanged.
    open func requireWritable(
        _ page: UInt8,
        data: Data,
        memoryMap: UltralightMemoryMap?,
        allowIrreversible: Bool
    ) async throws {
        try Self.requireWritable(page, memoryMap: memoryMap, allowIrreversible: allowIrreversible)
        guard page == 0x03, !allowIrreversible else { return }
        let current = try await readPages(startPage: 0x03).prefix(4)
        let unchanged = zip(current, data).allSatisfy { current, new in current | new == current }
        guard current.count == 4, unchanged else {
            throw NFCError.irreversibleWriteRefused(page: page)
        }
    }

    /// Refuse a write to the UID, lock, configuration, password or key pages
    /// unless the caller opted in. Page 3 (OTP) needs the tag's current value
    /// and is checked by the async overload.
    open class func requireWritable(
        _ page: UInt8,
        memoryMap: UltralightMemoryMap?,
        allowIrreversible: Bool
    ) throws {
        try memoryMap?.validate()
        guard !allowIrreversible else { return }
        switch page {
        case 0x00 ... 0x02:
            throw NFCError.irreversibleWriteRefused(page: page)
        case 0x03:
            return
        default:
            if let memoryMap, !memoryMap.isUserDataPage(page) {
                throw NFCError.irreversibleWriteRefused(page: page)
            }
        }
    }

    /// WRITE and COMPATIBILITY_WRITE answer with the 4-bit ACK `Ah`, which CoreNFC
    /// returns as the single byte `0Ah` (NAKs are `0h`/`1h`/`4h`/`5h`). An empty
    /// answer is not an acknowledgement.
    open class func requireACK(_ response: Data, page: UInt8) throws {
        guard response.first == 0x0A else {
            throw NFCError.writeFailed(page: page)
        }
    }
}
