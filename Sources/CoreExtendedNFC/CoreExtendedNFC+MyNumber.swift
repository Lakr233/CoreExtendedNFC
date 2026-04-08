import Foundation

public extension CoreExtendedNFC {
    /// Scan a Japanese My Number card and read the requested fields.
    ///
    /// - Note: Reading `.individualNumber` requires `cardInfoInputSupportPIN`.
    static func readMyNumberCard(
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil,
        message: String? = nil
    ) async throws -> MyNumberCardData {
        let manager = NFCSessionManager()
        let (rawInfo, transport) = try await manager.scan(
            for: [.iso14443],
            message: message ?? String(localized: "Hold your iPhone near your My Number card", bundle: .module)
        )

        do {
            let info = try await refineCardInfo(rawInfo, transport: transport)
            manager.setAlertMessage(String(localized: "Reading...", bundle: .module))
            let card = try await readMyNumberCard(
                info: info,
                transport: transport,
                items: items,
                cardInfoInputSupportPIN: cardInfoInputSupportPIN
            )
            manager.setAlertMessage(String(localized: "Done", bundle: .module))
            manager.invalidate()
            return card
        } catch {
            manager.invalidate(errorMessage: error.localizedDescription)
            throw error
        }
    }

    /// Read fields from a connected My Number card transport.
    static func readMyNumberCard(
        info _: CardInfo,
        transport: any NFCTagTransport,
        items: [MyNumberCardItem] = [.tokenInfo],
        cardInfoInputSupportPIN: String? = nil
    ) async throws -> MyNumberCardData {
        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            throw NFCError.unsupportedOperation("My Number card reading requires an ISO 7816 transport")
        }

        return try await MyNumberCardReader(transport: iso7816Transport).read(
            items: items,
            cardInfoInputSupportPIN: cardInfoInputSupportPIN
        )
    }

    /// Query remaining attempts for a My Number card PIN domain.
    static func lookupMyNumberRemainingPINAttempts(
        info _: CardInfo,
        transport: any NFCTagTransport,
        pinType: MyNumberPINType
    ) async throws -> Int {
        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            throw NFCError.unsupportedOperation("My Number PIN lookup requires an ISO 7816 transport")
        }

        return try await MyNumberCardReader(transport: iso7816Transport)
            .lookupRemainingPINAttempts(for: pinType)
    }
}
