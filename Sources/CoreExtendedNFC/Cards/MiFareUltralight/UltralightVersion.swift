import Foundation

/// Parsed response from GET_VERSION (0x60) command.
/// Used to distinguish Ultralight variants, NTAG models, and other NXP Type 2 tags.
public struct UltralightVersionResponse: Sendable, Equatable {
    public let header: UInt8
    public let vendorID: UInt8
    public let productType: UInt8
    public let productSubtype: UInt8
    public let majorVersion: UInt8
    public let minorVersion: UInt8
    public let storageSize: UInt8
    public let protocolType: UInt8

    public init(data: Data) throws {
        guard data.count >= 8 else {
            throw NFCError.invalidResponse(data)
        }
        header = data[data.startIndex]
        vendorID = data[data.startIndex + 1]
        productType = data[data.startIndex + 2]
        productSubtype = data[data.startIndex + 3]
        majorVersion = data[data.startIndex + 4]
        minorVersion = data[data.startIndex + 5]
        storageSize = data[data.startIndex + 6]
        protocolType = data[data.startIndex + 7]
    }

    /// Identify the exact card type from version response.
    public var cardType: CardType {
        guard vendorID == 0x04 else { return .mifareUltralight } // 0x04 = NXP
        // Ultralight EV1 and NTAG21x report major version 01h; NTAG210u (02h) and
        // NTAG213 TT (03h) share the NTAG210 / NTAG213 page layouts. Other majors
        // share storage codes but not memory layouts — e.g. Ultralight Nano 02h/03h
        // (11 pages, storage 0Bh) and NTAG 223 DNA 04h (60 pages, storage 0Fh) — so
        // they get the generic map rather than a wrong one (proxmark3
        // client/src/cmdhfmfu.c GetHF14AMfU_Type and the MAX_* page counts).
        let isNTAG210u = productType == 0x04 && majorVersion == 0x02 && storageSize == 0x0B
        let isNTAG213TT = productType == 0x04 && majorVersion == 0x03 && storageSize == 0x0F
        guard majorVersion == 0x01 || isNTAG210u || isNTAG213TT else { return .mifareUltralight }

        // productType: 0x03 = Ultralight, 0x04 = NTAG
        switch productType {
        case 0x03:
            // Ultralight family
            switch storageSize {
            case 0x0B:
                return .mifareUltralightEV1_MF0UL11 // 48 bytes (pages 0-16)
            case 0x0E:
                return .mifareUltralightEV1_MF0UL21 // 128 bytes (pages 0-40)
            default:
                return .mifareUltralight
            }
        case 0x04:
            // NTAG I2C (NT3H1x01 / NT3H2x11) reports product subtype 05h with
            // storage sizes that collide with NTAG216 (13h) but has a different
            // configuration and session-register map, so it must not get the
            // NTAG21x maps. NTAG21x uses subtypes 01h/02h/04h.
            guard productSubtype != 0x05 else { return .mifareUltralight }
            // NTAG family. Storage sizes from the NXP NTAG210/212 and
            // NTAG213/215/216 datasheets (GET_VERSION byte 6).
            switch storageSize {
            case 0x0B:
                return .ntag210 // 48 user bytes, 20 pages
            case 0x0E:
                return .ntag212 // 128 user bytes, 41 pages
            case 0x0F:
                return .ntag213 // 144 user bytes
            case 0x11:
                return .ntag215 // 504 user bytes
            case 0x13:
                return .ntag216 // 888 user bytes
            default:
                // Unknown NTAG size: fall back to the generic 16-page map so
                // NDEF writes can never reach an unknown config/PWD page.
                return .mifareUltralight
            }
        default:
            return .mifareUltralight
        }
    }

    /// Total number of pages on the tag.
    public var totalPages: UInt8 {
        UltralightMemoryMap.forType(cardType).totalPages
    }

    /// Number of user-writable data pages.
    public var userPages: UInt8 {
        let map = UltralightMemoryMap.forType(cardType)
        return map.userDataEnd - map.userDataStart + 1
    }
}

public extension UltralightCommands {
    /// GET_VERSION (0x60): Returns 8 bytes identifying the chip.
    func getVersion() async throws -> UltralightVersionResponse {
        let response = try await transport.send(Data([0x60]))
        return try UltralightVersionResponse(data: response)
    }
}
