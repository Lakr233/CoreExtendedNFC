import Foundation

public extension CoreExtendedNFC {
    /// Read transit card balance from a connected tag.
    /// Automatically detects Japan IC (including IruCa, PASPY and SAPICA), OKICA,
    /// Rakuten Edy, WAON, nanaco, Octopus, Singapore CEPAS, T-Money/Cashbee/Snapper
    /// (KS X 6924), or T-Union cards.
    /// Call directly after `NFCSessionManager.scan`, before `refineCardInfo` or other
    /// application-selection commands change the default application used by CEPAS.
    ///
    /// Detection order:
    /// 1. FeliCa system code → Japan IC (0003/80DE/8592/865E), OKICA (8FC1),
    ///    Octopus (8008), or the common area (FE00), where the Rakuten Edy, WAON,
    ///    and nanaco balance services are tried in that order
    /// 2. ISO 7816 → probe Singapore CEPAS purse
    /// 3. ISO 7816 → try KS X 6924 AIDs (T-Money / Snapper, Cashbee, MOIBA, K-Cash)
    /// 4. ISO 7816 → try T-Union AID
    ///
    /// Only ``NFCError/applicationNotFound(aid:)`` (or ``NFCError/tagNotSupported``)
    /// from a reader moves on to the next one; any other error is rethrown. When no
    /// reader recognizes the card, ``NFCError/tagNotSupported`` is thrown.
    static func readTransitBalance(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> TransitBalance {
        if info.type.family == .felica {
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa transit reading requires a FeliCa transport")
            }
            if JapanICConstants.cardNamesBySystemCode[felicaTransport.systemCode] != nil {
                return try await readJapanICBalance(transport: felicaTransport)
            }
            if felicaTransport.systemCode == OKICAConstants.systemCode {
                return try await readOKICABalance(transport: felicaTransport)
            }
            if felicaTransport.systemCode == OctopusConstants.systemCode {
                return try await readOctopusBalance(transport: felicaTransport)
            }
            if felicaTransport.systemCode == FeliCaCommonAreaConstants.systemCode {
                // One common area can hold several purses; each reader checks for its own
                // balance service and throws tagNotSupported when it is missing.
                do {
                    return try await readEdyBalance(transport: felicaTransport)
                } catch NFCError.tagNotSupported {}
                do {
                    return try await readWAONBalance(transport: felicaTransport)
                } catch NFCError.tagNotSupported {}
                return try await readNanacoBalance(transport: felicaTransport)
            }
            throw NFCError.tagNotSupported
        }

        if let iso7816Transport = transport as? any ISO7816TagTransporting {
            // CEPAS depends on the initial application; probe before selecting other AIDs.
            if let balance = try await CEPASReader(transport: iso7816Transport).readIfSupported() {
                return balance
            }

            // Try Korea KS X 6924. Only "no AID selected" means "not this card"; once an AID
            // is selected, a rejected GET BALANCE or other failure surfaces to the caller.
            do {
                return try await readKoreaTransitBalance(transport: iso7816Transport)
            } catch NFCError.applicationNotFound, NFCError.tagNotSupported {
                // No KS X 6924 AID was selectable; try next
            }

            // Try China T-Union, with the same rule.
            do {
                return try await readChinaTransitBalance(transport: iso7816Transport)
            } catch NFCError.applicationNotFound, NFCError.tagNotSupported {
                // T-Union AID not selectable either
            }
        }

        throw NFCError.tagNotSupported
    }

    /// Read Japan FeliCa IC card balance + history.
    ///
    /// Supports Suica, PASMO, ICOCA, Kitaca, TOICA, manaca, SUGOCA, nimoca, Hayakaken,
    /// IruCa, PASPY and SAPICA. Register the relevant system code (`0003`, `80DE`,
    /// `8592` or `865E`) under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    static func readJapanICBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await JapanICReader(transport: transport).readBalanceAndHistory()
    }

    /// Read Okinawa OKICA balance and history. Register system code `8FC1` in Info.plist.
    static func readOKICABalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await OKICAReader(transport: transport).readBalanceAndHistory()
    }

    /// Read Hong Kong Octopus balance.
    static func readOctopusBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await OctopusReader(transport: transport).readBalance()
    }

    /// Read Rakuten Edy balance + history.
    ///
    /// The consumer app must register system code `0xFE00` in Info.plist
    /// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    static func readEdyBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await EdyReader(transport: transport).readBalanceAndHistory()
    }

    /// Read WAON balance + history; the point balance is in `metadata["points"]`.
    ///
    /// The consumer app must register system code `0xFE00` in Info.plist
    /// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    static func readWAONBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await WAONReader(transport: transport).readBalanceAndHistory()
    }

    /// Read nanaco balance + history; the point balance is in `metadata["points"]`.
    ///
    /// The consumer app must register system code `0xFE00` in Info.plist
    /// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    static func readNanacoBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await NanacoReader(transport: transport).readBalanceAndHistory()
    }

    /// Read KS X 6924 balance + history (T-Money, Cashbee, MOIBA, K-Cash; Snapper is reported in NZD).
    static func readKoreaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await KSX6924Reader(transport: transport).readBalanceAndHistory()
    }

    /// Read China T-Union balance.
    ///
    /// Note: Beijing Yikatong uses a short AID outside iOS CoreNFC's selectable AID path.
    static func readChinaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await TUnionReader(transport: transport).readBalance()
    }
}
