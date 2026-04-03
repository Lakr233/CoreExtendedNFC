import Foundation

public extension CoreExtendedNFC {
    /// Read transit card balance from a connected tag.
    /// Automatically detects Japan IC (FeliCa), T-Money/Cashbee (KS X 6924), or T-Union cards.
    ///
    /// Detection order:
    /// 1. FeliCa with system code 0x0003 → Japan IC
    /// 2. ISO 7816 → try KS X 6924 AIDs (T-Money, Cashbee, MOIBA, K-Cash)
    /// 3. ISO 7816 → try T-Union AID
    static func readTransitBalance(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> TransitBalance {
        // Japan FeliCa IC cards
        if info.type.family == .felica {
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa transit reading requires a FeliCa transport")
            }
            return try await readJapanICBalance(transport: felicaTransport)
        }

        // ISO 7816 cards: try Korea then China
        if let iso7816Transport = transport as? any ISO7816TagTransporting {
            // Try Korea KS X 6924 first — only catch "not this card" errors
            do {
                return try await readKoreaTransitBalance(transport: iso7816Transport)
            } catch NFCError.unsupportedOperation {
                // Not a Korean transit card, try next
            } catch NFCError.unexpectedStatusWord {
                // AID selection rejected by card, try next
            }

            // Try China T-Union
            do {
                return try await readChinaTransitBalance(transport: iso7816Transport)
            } catch NFCError.unsupportedOperation {
                // Not a T-Union card either
            } catch NFCError.unexpectedStatusWord {
                // AID selection rejected by card
            }
        }

        throw NFCError.unsupportedOperation("No supported transit card detected")
    }

    /// Read Japan FeliCa IC card balance + history.
    ///
    /// Supports Suica, PASMO, ICOCA, Kitaca, TOICA, manaca, SUGOCA, nimoca, Hayakaken.
    /// The consumer app must register system code `0x0003` in Info.plist
    /// under `com.apple.developer.nfc.readersession.felicasystemcodes`.
    static func readJapanICBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await JapanICReader(transport: transport).readBalanceAndHistory()
    }

    /// Read Korea T-Money/Cashbee balance + history (KS X 6924).
    static func readKoreaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await KSX6924Reader(transport: transport).readBalanceAndHistory()
    }

    /// Read China T-Union balance.
    ///
    /// Note: Beijing Yikatong is not supported on iOS (short AID restriction).
    static func readChinaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await TUnionReader(transport: transport).readBalance()
    }
}
