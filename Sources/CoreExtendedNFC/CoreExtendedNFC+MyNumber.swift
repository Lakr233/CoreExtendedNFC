import Foundation

public extension CoreExtendedNFC {
    /// Scan a Japanese My Number card and read the requested fields.
    ///
    /// - Note: Reading `.individualNumber` requires `cardInfoInputSupportPIN`; without it
    ///   ``NFCError/pinRequired(_:)`` is thrown.
    /// - Throws: ``NFCError``. When the user dismisses the NFC sheet or the calling task
    ///   is cancelled, the error's ``Swift/Error/isNFCCancellation`` is `true`; apps
    ///   usually stay silent then.
    /// - Parameters:
    ///   - items: Which fields to read (default: token info).
    ///   - cardInfoInputSupportPIN: The 4-digit card-info-input-support PIN, required
    ///     for `.individualNumber`.
    ///   - message: The alert message shown during NFC scanning.
    ///   - manager: The session manager that runs the scan. Pass your own instance,
    ///     or a subclass, to customize the session. It is invalidated before returning.
    ///   - onProgress: Called with each localized progress message, which is also shown
    ///     on the NFC sheet.
    static func readMyNumberCard(
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil,
        message: String? = nil,
        manager: NFCSessionManager = NFCSessionManager(),
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> MyNumberCardData {
        let (_, transport) = try await manager.scan(
            for: [.iso14443],
            message: message ?? String(localized: "Hold your iPhone near your My Number card", bundle: .module)
        )

        do {
            let card = try await readMyNumberCard(
                transport: transport,
                items: items,
                cardInfoInputSupportPIN: cardInfoInputSupportPIN,
                onProgress: { msg in
                    manager.setAlertMessage(msg)
                    onProgress?(msg)
                }
            )
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return card
        } catch {
            throw manager.invalidateAfterFailure(error)
        }
    }

    /// Read fields from a connected My Number card transport.
    ///
    /// Neither starts nor ends an NFC session.
    ///
    /// - Parameters:
    ///   - transport: A connected ISO 7816 transport to the card.
    ///   - items: Which fields to read (default: token info).
    ///   - cardInfoInputSupportPIN: The 4-digit card-info-input-support PIN, required
    ///     for `.individualNumber`.
    ///   - onProgress: Called with a localized message before each field is read.
    /// - Throws: ``NFCError/unsupportedOperation(_:)`` for a non-ISO 7816 transport,
    ///   otherwise the errors of ``MyNumberCardReader/read(items:cardInfoInputSupportPIN:onProgress:)``.
    static func readMyNumberCard(
        transport: any NFCTagTransport,
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil,
        onProgress: (@Sendable (String) -> Void)? = nil
    ) async throws -> MyNumberCardData {
        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            throw NFCError.unsupportedOperation("My Number card reading requires an ISO 7816 transport")
        }

        return try await MyNumberCardReader(transport: iso7816Transport).read(
            items: items,
            cardInfoInputSupportPIN: cardInfoInputSupportPIN,
            onProgress: onProgress
        )
    }

    /// Read fields from a connected My Number card transport.
    ///
    /// The `info` argument was never used; call
    /// ``readMyNumberCard(transport:items:cardInfoInputSupportPIN:onProgress:)``.
    @available(*, deprecated, renamed: "readMyNumberCard(transport:items:cardInfoInputSupportPIN:onProgress:)")
    static func readMyNumberCard(
        info _: CardInfo,
        transport: any NFCTagTransport,
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil
    ) async throws -> MyNumberCardData {
        try await readMyNumberCard(
            transport: transport,
            items: items,
            cardInfoInputSupportPIN: cardInfoInputSupportPIN
        )
    }

    /// Query remaining attempts for a My Number card PIN domain.
    ///
    /// Neither starts nor ends an NFC session.
    static func lookupMyNumberRemainingPINAttempts(
        transport: any NFCTagTransport,
        pinType: MyNumberPINType
    ) async throws -> Int {
        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            throw NFCError.unsupportedOperation("My Number PIN lookup requires an ISO 7816 transport")
        }

        return try await MyNumberCardReader(transport: iso7816Transport)
            .lookupRemainingPINAttempts(for: pinType)
    }

    /// Query remaining attempts for a My Number card PIN domain.
    ///
    /// The `info` argument was never used; call
    /// ``lookupMyNumberRemainingPINAttempts(transport:pinType:)``.
    @available(*, deprecated, renamed: "lookupMyNumberRemainingPINAttempts(transport:pinType:)")
    static func lookupMyNumberRemainingPINAttempts(
        info _: CardInfo,
        transport: any NFCTagTransport,
        pinType: MyNumberPINType
    ) async throws -> Int {
        try await lookupMyNumberRemainingPINAttempts(transport: transport, pinType: pinType)
    }
}
