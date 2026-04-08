import Foundation

/// High-level card family grouping.
public enum CardFamily: Sendable, Equatable, Codable {
    case mifareUltralight
    case mifareClassic
    case mifarePlus
    case mifareDesfire
    case type4
    case ntag
    case felica
    case iso15693
    case jewelTopaz
    case iso14443B
    case passport
    case unknown
}

/// Specific card type identified from ATQA+SAK and/or GET_VERSION.
public enum CardType: Sendable, Equatable, Codable {
    // MIFARE Ultralight family
    case mifareUltralight
    case mifareUltralightC
    case mifareUltralightEV1_MF0UL11
    case mifareUltralightEV1_MF0UL21

    // NTAG family
    case ntag210
    case ntag212
    case ntag213
    case ntag215
    case ntag216

    // MIFARE Classic family (iOS: identification only, not operable)
    case mifareClassic1K
    case mifareClassic4K
    case mifareMini

    // MIFARE Plus family
    case mifarePlusSL1_2K
    case mifarePlusSL1_4K
    case mifarePlusSL2_2K
    case mifarePlusSL2_4K
    case mifarePlusSL3_2K
    case mifarePlusSL3_4K

    // MIFARE DESFire family
    case mifareDesfire
    case mifareDesfireEV1
    case mifareDesfireEV2
    case mifareDesfireEV3

    /// NFC Forum Type 4 family
    case type4NDEF

    // FeliCa family
    case felicaLite
    case felicaLiteS
    case felicaStandard

    // ISO 15693 family
    case iso15693_ICODE_SLIX
    case iso15693_ST25TV
    case iso15693_generic

    /// Passport / eMRTD
    case ePassport
    /// Japanese Individual Number Card (My Number Card).
    case myNumberCard

    // Other
    case jewelTopaz
    case iso14443B_generic
    case smartMX
    case unknown(atqa: Data, sak: UInt8)

    /// The card family this type belongs to.
    public var family: CardFamily {
        switch self {
        case .mifareUltralight, .mifareUltralightC,
             .mifareUltralightEV1_MF0UL11, .mifareUltralightEV1_MF0UL21:
            .mifareUltralight
        case .ntag210, .ntag212, .ntag213, .ntag215, .ntag216:
            .ntag
        case .mifareClassic1K, .mifareClassic4K, .mifareMini:
            .mifareClassic
        case .mifarePlusSL1_2K, .mifarePlusSL1_4K,
             .mifarePlusSL2_2K, .mifarePlusSL2_4K,
             .mifarePlusSL3_2K, .mifarePlusSL3_4K:
            .mifarePlus
        case .mifareDesfire, .mifareDesfireEV1, .mifareDesfireEV2, .mifareDesfireEV3:
            .mifareDesfire
        case .type4NDEF:
            .type4
        case .felicaLite, .felicaLiteS, .felicaStandard:
            .felica
        case .iso15693_ICODE_SLIX, .iso15693_ST25TV, .iso15693_generic:
            .iso15693
        case .jewelTopaz:
            .jewelTopaz
        case .iso14443B_generic:
            .iso14443B
        case .ePassport:
            .passport
        case .myNumberCard:
            .iso14443B
        case .smartMX, .unknown:
            .unknown
        }
    }

    /// Whether iOS can perform operations beyond identification on this card type.
    /// MIFARE Classic uses Crypto1 which iOS hardware cannot handle.
    public var isOperableOnIOS: Bool {
        switch self {
        case .mifareClassic1K, .mifareClassic4K, .mifareMini,
             .mifarePlusSL1_2K, .mifarePlusSL1_4K:
            false
        case .jewelTopaz:
            false
        case .unknown:
            false
        default:
            true
        }
    }

    /// Human-readable description of the card type.
    public var description: String {
        switch self {
        case .mifareUltralight: "MIFARE Ultralight"
        case .mifareUltralightC: "MIFARE Ultralight C"
        case .mifareUltralightEV1_MF0UL11: "MIFARE Ultralight EV1 (MF0UL11)"
        case .mifareUltralightEV1_MF0UL21: "MIFARE Ultralight EV1 (MF0UL21)"
        case .ntag210: "NTAG210"
        case .ntag212: "NTAG212"
        case .ntag213: "NTAG213"
        case .ntag215: "NTAG215"
        case .ntag216: "NTAG216"
        case .mifareClassic1K: "MIFARE Classic 1K"
        case .mifareClassic4K: "MIFARE Classic 4K"
        case .mifareMini: "MIFARE Mini 0.3K"
        case .mifarePlusSL1_2K: "MIFARE Plus 2K (SL1)"
        case .mifarePlusSL1_4K: "MIFARE Plus 4K (SL1)"
        case .mifarePlusSL2_2K: "MIFARE Plus 2K (SL2)"
        case .mifarePlusSL2_4K: "MIFARE Plus 4K (SL2)"
        case .mifarePlusSL3_2K: "MIFARE Plus 2K (SL3)"
        case .mifarePlusSL3_4K: "MIFARE Plus 4K (SL3)"
        case .mifareDesfire: "MIFARE DESFire"
        case .mifareDesfireEV1: "MIFARE DESFire EV1"
        case .mifareDesfireEV2: "MIFARE DESFire EV2"
        case .mifareDesfireEV3: "MIFARE DESFire EV3"
        case .type4NDEF: "NFC Forum Type 4 Tag"
        case .felicaLite: "FeliCa Lite"
        case .felicaLiteS: "FeliCa Lite-S"
        case .felicaStandard: "FeliCa Standard"
        case .iso15693_ICODE_SLIX: "ICODE SLIX (ISO 15693)"
        case .iso15693_ST25TV: "ST25TV (ISO 15693)"
        case .iso15693_generic: "ISO 15693"
        case .jewelTopaz: "Jewel/Topaz (Type 1)"
        case .ePassport: "ePassport (eMRTD)"
        case .myNumberCard: "Japanese My Number Card"
        case .iso14443B_generic: "ISO 14443-B"
        case .smartMX: "SmartMX / Generic ISO 7816"
        case let .unknown(atqa, sak):
            "Unknown (ATQA: \(atqa.hexString), SAK: \(String(format: "%02X", sak)))"
        }
    }
}

public extension CardFamily {
    /// Human-readable description of the broader card family.
    var description: String {
        switch self {
        case .mifareUltralight:
            "MIFARE Ultralight"
        case .mifareClassic:
            "MIFARE Classic"
        case .mifarePlus:
            "MIFARE Plus"
        case .mifareDesfire:
            "MIFARE DESFire"
        case .type4:
            "NFC Forum Type 4"
        case .ntag:
            "NTAG"
        case .felica:
            "FeliCa"
        case .iso15693:
            "ISO 15693"
        case .jewelTopaz:
            "Jewel / Topaz"
        case .iso14443B:
            "ISO 14443-B"
        case .passport:
            "Passport / eMRTD"
        case .unknown:
            "Unknown"
        }
    }
}
