import Foundation

extension CoreExtendedNFC {
    /// Read transit card balance from a connected tag.
    /// Automatically detects Japan IC (FeliCa), Octopus, Singapore CEPAS,
    /// T-Money/Cashbee/Snapper (KS X 6924), or T-Union cards.
    /// Call directly after `NFCSessionManager.scan`, before `refineCardInfo` or other
    /// application-selection commands change the default application used by CEPAS.
    ///
    /// Detection order:
    /// 1. FeliCa system code → Japan IC or Octopus
    /// 2. ISO 7816 → probe Singapore CEPAS purse
    /// 3. ISO 7816 → try KS X 6924 AIDs (T-Money / Snapper, Cashbee, MOIBA, K-Cash)
    /// 4. ISO 7816 → try T-Union AID
    public static func readTransitBalance(
        info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> TransitBalance {
        if info.type.family == .felica {
            guard let felicaTransport = transport as? any FeliCaTagTransporting else {
                throw NFCError.unsupportedOperation("FeliCa transit reading requires a FeliCa transport")
            }
            if felicaTransport.systemCode == JapanICConstants.systemCode {
                return try await readJapanICBalance(transport: felicaTransport)
            }
            if felicaTransport.systemCode == OctopusConstants.systemCode {
                return try await readOctopusBalance(transport: felicaTransport)
            }
            throw NFCError.unsupportedOperation("Unsupported FeliCa transit system code \(felicaTransport.systemCode.hexString)")
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
            } catch NFCError.unsupportedOperation {
                // No KS X 6924 AID was selectable; try next
            }

            // Try China T-Union, with the same rule.
            do {
                return try await readChinaTransitBalance(transport: iso7816Transport)
            } catch NFCError.unsupportedOperation {
                // T-Union AID not selectable either
            }
        }

        throw NFCError.unsupportedOperation("No supported transit card detected")
    }

    /// Read Japan FeliCa IC card balance + history.
    ///
    /// Supports Suica, PASMO, ICOCA, Kitaca, TOICA, manaca, SUGOCA, nimoca, Hayakaken.
    /// The consumer app must register system code `0x0003` in Info.plist
    /// under `com.apple.developer.nfc.readersession.felicasystemcodes`.
    public static func readJapanICBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await JapanICReader(transport: transport).readBalanceAndHistory()
    }

    /// Read Hong Kong Octopus balance.
    public static func readOctopusBalance(
        transport: any FeliCaTagTransporting
    ) async throws -> TransitBalance {
        try await OctopusReader(transport: transport).readBalance()
    }

    /// Read KS X 6924 balance + history (T-Money, Cashbee, MOIBA, K-Cash; Snapper is reported in NZD).
    public static func readKoreaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await KSX6924Reader(transport: transport).readBalanceAndHistory()
    }

    /// Read China T-Union balance.
    ///
    /// Note: Beijing Yikatong uses a short AID outside iOS CoreNFC's selectable AID path.
    public static func readChinaTransitBalance(
        transport: any ISO7816TagTransporting
    ) async throws -> TransitBalance {
        try await TUnionReader(transport: transport).readBalance()
    }
}
