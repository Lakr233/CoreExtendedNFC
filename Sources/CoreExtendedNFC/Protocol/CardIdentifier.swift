import Foundation

/// Identifies card type from ATQA and SAK bytes.
/// Ported from libnfc target-subr.c lookup tables.
///
/// ## ATQA byte order
/// ISO/IEC 14443-3 transmits ATQA least-significant byte first (an NTAG answers
/// `44 00` on the air), while NXP AN10833 and libnfc write the value as a 16-bit
/// number (`0x0044`). This library's convention, for ``identify(atqa:sak:)`` and for
/// `CardInfo.atqa`, is the AN10833 notation: most-significant byte first, so an NTAG
/// is `Data([0x00, 0x44])`. Convert wire-order bytes with ``atqaValue(wireOrder:)``.
public enum CardIdentifier {
    /// Identify a card from its ATQA (2 bytes, most-significant byte first as written
    /// in AN10833, e.g. `00 44`) and SAK (1 byte).
    /// Note: Ultralight and NTAG share the same ATQA/SAK — use GET_VERSION (0x60) to distinguish.
    public static func identify(atqa: Data, sak: UInt8) -> CardType {
        guard atqa.count >= 2 else { return .unknown(atqa: atqa, sak: sak) }

        let atqaValue = UInt16(atqa[atqa.startIndex]) << 8 | UInt16(atqa[atqa.startIndex + 1])
        return identify(atqaValue: atqaValue, sak: sak, atqaBytes: atqa)
    }

    /// Identify a card from its ATQA as a 16-bit value (e.g. `0x0044`) and SAK.
    public static func identify(atqaValue: UInt16, sak: UInt8) -> CardType {
        identify(atqaValue: atqaValue, sak: sak, atqaBytes: Data([UInt8(atqaValue >> 8), UInt8(atqaValue & 0xFF)]))
    }

    /// The 16-bit ATQA value from the two bytes in ISO/IEC 14443-3 transmission order
    /// (least-significant byte first, e.g. `44 00` → `0x0044`). `nil` unless exactly 2 bytes.
    public static func atqaValue(wireOrder bytes: Data) -> UInt16? {
        guard bytes.count == 2 else { return nil }
        return UInt16(bytes[bytes.startIndex + 1]) << 8 | UInt16(bytes[bytes.startIndex])
    }

    private static func identify(atqaValue: UInt16, sak: UInt8, atqaBytes atqa: Data) -> CardType {

        // Match the most specific ATQA+SAK combinations first.
        // Reference: NXP AN10833 "MIFARE Type Identification Procedure"

        // MIFARE DESFire: ATQA 0x0344, SAK 0x20
        if atqaValue == 0x0344, sak == 0x20 {
            return .mifareDesfire
        }

        // MIFARE Ultralight / Ultralight C / NTAG: ATQA 0x0044, SAK 0x00
        // Cannot distinguish Ultralight vs NTAG from ATQA/SAK alone — needs GET_VERSION.
        if atqaValue == 0x0044, sak == 0x00 {
            return .mifareUltralight
        }

        // MIFARE Mini: ATQA 0x0004 (mask 0xFF0F), SAK 0x09
        if atqaValue & 0xFF0F == 0x0004, sak == 0x09 {
            return .mifareMini
        }

        // MIFARE Classic 1K: ATQA 0x0004 (mask 0xFF0F), SAK 0x08
        if atqaValue & 0xFF0F == 0x0004, sak == 0x08 {
            return .mifareClassic1K
        }

        // MIFARE Classic 4K: ATQA 0x0002 (mask 0xFF0F), SAK 0x18
        if atqaValue & 0xFF0F == 0x0002, sak == 0x18 {
            return .mifareClassic4K
        }

        // MIFARE Plus uses several ATQA values; SAK selects the security level.
        let isPlusATQA = (atqaValue == 0x0004 || atqaValue == 0x0002
            || atqaValue == 0x0044 || atqaValue == 0x0042)
        if isPlusATQA {
            switch sak {
            case 0x08: return .mifarePlusSL1_2K
            case 0x18: return .mifarePlusSL1_4K
            case 0x10: return .mifarePlusSL2_2K
            case 0x11: return .mifarePlusSL2_4K
            case 0x20:
                // SAK 0x20 with non-DESFire ATQA maps to MIFARE Plus SL3.
                if atqaValue == 0x0004 || atqaValue == 0x0044 {
                    return .mifarePlusSL3_2K
                } else {
                    return .mifarePlusSL3_4K
                }
            default:
                break
            }
        }

        // SmartMX matches a broader ATQA mask with SAK 0x00.
        let isSmartMXATQA = (atqaValue & 0xF0FF == 0x0004
            || atqaValue & 0xF0FF == 0x0002
            || atqaValue & 0xF0FF == 0x0048)
        if isSmartMXATQA, sak == 0x00 {
            return .smartMX
        }

        // SAK-only fallback matching
        switch sak {
        case 0x00:
            return .mifareUltralight
        case 0x08:
            return .mifareClassic1K
        case 0x09:
            return .mifareMini
        case 0x18:
            return .mifareClassic4K
        case 0x20:
            return .mifareDesfire
        default:
            return .unknown(atqa: atqa, sak: sak)
        }
    }
}
