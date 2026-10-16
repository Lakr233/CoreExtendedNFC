import Foundation

enum CardInfoRefiner {
    static func refine(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        switch info.type {
        case .mifareUltralight:
            try await refineUltralight(info, transport: transport)
        case .mifareClassic1K, .mifareClassic4K, .mifareMini:
            try await refinePossibleUltralight(info, transport: transport)
        case .smartMX:
            try await refineISO7816(info, transport: transport)
        case .felicaStandard:
            try await refineFeliCaLite(info, transport: transport)
        default:
            info
        }
    }

    private static func refineUltralight(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        let commands = UltralightCommands(transport: transport)
        do {
            let version = try await commands.getVersion()
            return updated(info, type: version.cardType)
        } catch NFCError.invalidResponse {
            // The tag answered GET_VERSION with a NAK (short frame), so it is
            // MF0ICU1 (Ultralight) or MF0ICU2 (Ultralight C). Tell them apart by
            // memory size with a plain READ instead of an AUTHENTICATE probe:
            // a `1A 00` probe leaves an Ultralight C mid-authentication, and the
            // MF0ICU2 datasheet ("Authentication" section) aborts that state with
            // a NAK on any command other than the AF second step, so the dump
            // that follows would fail.
            if try await commands.probeUltralightCMemory() {
                return updated(info, type: .mifareUltralightC)
            }
            return info
        } catch where isSessionTerminating(error) && !isMissingTagResponse(error) {
            throw error
        } catch {
            return info
        }
    }

    private static func refinePossibleUltralight(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        let commands = UltralightCommands(transport: transport)
        do {
            let manufacturerPages = try await commands.readPages(startPage: 0x00)
            guard matchesUltralightManufacturerPages(manufacturerPages, uid: info.uid) else {
                return info
            }
            return try await refineUltralight(updated(info, type: .mifareUltralight), transport: transport)
        } catch where isSessionTerminating(error) && !isMissingTagResponse(error) {
            throw error
        } catch {
            return info
        }
    }

    private static func matchesUltralightManufacturerPages(_ pages: Data, uid: Data) -> Bool {
        guard uid.count >= 7, pages.count >= 12 else { return false }

        let bytes = [UInt8](pages.prefix(12))
        let uidBytes = [UInt8](uid.prefix(7))
        let expectedBCC0 = 0x88 ^ uidBytes[0] ^ uidBytes[1] ^ uidBytes[2]
        let expectedBCC1 = uidBytes[3] ^ uidBytes[4] ^ uidBytes[5] ^ uidBytes[6]

        return bytes[0] == uidBytes[0]
            && bytes[1] == uidBytes[1]
            && bytes[2] == uidBytes[2]
            && bytes[3] == expectedBCC0
            && bytes[4] == uidBytes[3]
            && bytes[5] == uidBytes[4]
            && bytes[6] == uidBytes[5]
            && bytes[7] == uidBytes[6]
            && bytes[8] == expectedBCC1
    }

    /// FeliCa Lite and Lite-S both use System Code 0x88B4 (FeliCa Lite /
    /// Lite-S User's Manuals). The PMm IC-type byte (0xF0 Lite, 0xF1 Lite-S)
    /// would tell them apart, but CoreNFC does not expose PMm on
    /// `NFCFeliCaTag` without a separate polling call, so `CardInfo` doesn't
    /// carry it. Instead use the memory map: only Lite-S has block 0x90
    /// (WCNT, readable without authentication through service 0x000B); on a
    /// Lite that block number is rejected with a non-zero status flag.
    private static func refineFeliCaLite(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        guard info.systemCode == FeliCaLiteConstants.systemCode,
              let felica = transport as? any FeliCaTagTransporting
        else {
            return info
        }
        do {
            let blocks = try await felica.readWithoutEncryption(
                serviceCode: FeliCaLiteConstants.readOnlyServiceCode,
                blockList: [FeliCaFrame.blockListElement(blockNumber: FeliCaLiteConstants.writeCounterBlock)]
            )
            return updated(info, type: blocks.isEmpty ? .felicaLite : .felicaLiteS)
        } catch NFCError.felicaBlockReadFailed {
            return updated(info, type: .felicaLite)
        } catch where isSessionTerminating(error) {
            throw error
        } catch {
            return info
        }
    }

    private static func refineISO7816(
        _ info: CardInfo,
        transport: any NFCTagTransport
    ) async throws -> CardInfo {
        if let type = detectFromMetadata(initialAID: info.initialSelectedAID, historicalBytes: info.historicalBytes) {
            return updated(info, type: type)
        }

        guard let iso7816Transport = transport as? any ISO7816TagTransporting else {
            return info
        }

        if let detectedType = await detectByProbing(transport: iso7816Transport) {
            return updated(info, type: detectedType)
        }

        return info
    }

    private static func detectFromMetadata(
        initialAID: String?,
        historicalBytes: Data?
    ) -> CardType? {
        if let hintedType = ISO7816Application.match(aid: initialAID)?.hintedCardType {
            return hintedType
        }

        if let historicalBytes {
            if historicalBytes.range(of: PassportConstants.eMRTDAID) != nil {
                return .ePassport
            }
            if historicalBytes.range(of: Type4Constants.ndefAID) != nil {
                return .type4NDEF
            }
        }

        return nil
    }

    private static func detectByProbing(
        transport: any ISO7816TagTransporting
    ) async -> CardType? {
        // Keep a successful passport SELECT as a fallback signal only.
        // Some ISO 7816 tags are permissive about AID selection, so returning
        // ePassport immediately would misclassify Type 4 NDEF tags.
        var passportSelectSucceeded = false
        do {
            let response = try await transport.sendAPDU(CommandAPDU.selectPassportApplication())
            passportSelectSucceeded = response.isSuccess
        } catch {}

        do {
            _ = try await Type4Reader(transport: transport).readCapabilityContainer()
            return .type4NDEF
        } catch {}

        do {
            let version = try await DESFireCommands(transport: transport).getVersion()
            return version.cardType
        } catch {}

        if passportSelectSucceeded {
            return .ePassport
        }

        return nil
    }

    private static func updated(_ info: CardInfo, type: CardType) -> CardInfo {
        CardInfo(
            type: type,
            uid: info.uid,
            atqa: info.atqa,
            sak: info.sak,
            ats: info.ats,
            historicalBytes: info.historicalBytes,
            initialSelectedAID: info.initialSelectedAID,
            systemCode: info.systemCode,
            idm: info.idm,
            icManufacturer: info.icManufacturer
        )
    }
}

private enum FeliCaLiteConstants {
    /// System Code shared by FeliCa Lite and Lite-S (big-endian, as CoreNFC reports it).
    static let systemCode = Data([0x88, 0xB4])
    /// Read-only (no authentication) service 0x000B, little-endian.
    static let readOnlyServiceCode = Data([0x0B, 0x00])
    /// WCNT block, present on FeliCa Lite-S only.
    static let writeCounterBlock: UInt16 = 0x90
}
