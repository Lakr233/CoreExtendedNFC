import Foundation

/// ISO/IEC 7816-4 response-status handling shared by transports and card readers.
///
/// Pure logic: the caller supplies the function that sends one APDU.
public enum APDUExchange {
    /// Default cap on `GET RESPONSE` round trips for one command.
    /// 256 frames of up to 256 bytes covers the largest extended Ne (65 536 bytes).
    public static let defaultMaxGetResponseFrames = 256

    /// Send `apdu` and resolve the ISO 7816-4 transmission statuses (§5.1.3):
    ///
    /// - `6Cxx` (wrong Le): the command is re-issued once with Ne = `xx` (`00` = 256)
    ///   when `retryOnWrongLength` is `true`.
    /// - `61xx` (more data): `GET RESPONSE` is sent with Le = `xx` until the card stops
    ///   answering `61xx`, concatenating the data. A `6Cxx` answer to a GET RESPONSE
    ///   re-issues it with the corrected Le.
    ///
    /// The returned response carries all collected data and the final status word.
    /// Throws ``NFCError/responseChainTooLong(maxFrames:)`` when the card asks for more
    /// than `maxGetResponseFrames` follow-up exchanges, and `CancellationError` when the
    /// calling task is cancelled between frames.
    public static func transmit(
        _ apdu: CommandAPDU,
        maxGetResponseFrames: Int = defaultMaxGetResponseFrames,
        retryOnWrongLength: Bool = true,
        using send: (CommandAPDU) async throws -> ResponseAPDU
    ) async throws -> ResponseAPDU {
        var response = try await send(apdu)

        if retryOnWrongLength, let corrected = response.correctedExpectedLength {
            try Task.checkCancellation()
            response = try await send(apdu.withExpectedResponseLength(corrected))
        }

        var collected = response.data
        var frames = 0

        while response.needsGetResponse || (frames > 0 && response.correctedExpectedLength != nil) {
            frames += 1
            guard frames <= maxGetResponseFrames else {
                throw NFCError.responseChainTooLong(maxFrames: maxGetResponseFrames)
            }
            try Task.checkCancellation()

            // In both 61xx and 6Cxx, SW2 is the Le to ask for next.
            response = try await send(.getResponse(length: response.sw2))
            collected.append(response.data)
        }

        return ResponseAPDU(data: collected, sw1: response.sw1, sw2: response.sw2)
    }
}
