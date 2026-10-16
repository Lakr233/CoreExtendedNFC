import Foundation

/// ISO 14443 helpers ported from libnfc `iso14443-subr.c`.
public enum ISO14443 {
    // MARK: - CRC

    /// CRC_A (ISO 14443-3A). Initial value: 0x6363.
    public static func crcA(_ data: Data) -> (UInt8, UInt8) {
        var wCrc: UInt32 = 0x6363
        for byte in data {
            var bt = byte ^ UInt8(wCrc & 0xFF)
            bt = bt ^ (bt << 4)
            let bt32 = UInt32(bt)
            wCrc = (wCrc >> 8) ^ (bt32 << 8) ^ (bt32 << 3) ^ (bt32 >> 4)
        }
        return (UInt8(wCrc & 0xFF), UInt8((wCrc >> 8) & 0xFF))
    }

    /// CRC_B (ISO 14443-3B). Initial value: 0xFFFF, final NOT.
    public static func crcB(_ data: Data) -> (UInt8, UInt8) {
        var wCrc: UInt32 = 0xFFFF
        for byte in data {
            var bt = byte ^ UInt8(wCrc & 0xFF)
            bt = bt ^ (bt << 4)
            let bt32 = UInt32(bt)
            wCrc = (wCrc >> 8) ^ (bt32 << 8) ^ (bt32 << 3) ^ (bt32 >> 4)
        }
        wCrc = ~wCrc
        return (UInt8(wCrc & 0xFF), UInt8((wCrc >> 8) & 0xFF))
    }

    /// Append CRC_A to data.
    public static func appendCrcA(_ data: inout Data) {
        let (lo, hi) = crcA(data)
        data.append(lo)
        data.append(hi)
    }

    /// Append CRC_B to data.
    public static func appendCrcB(_ data: inout Data) {
        let (lo, hi) = crcB(data)
        data.append(lo)
        data.append(hi)
    }

    // MARK: - UID Cascade

    /// Add cascade tags (0x88) to a UID per ISO 14443-3 section 6.4.4.
    /// - 4-byte UID: returned as-is
    /// - 7-byte UID: [0x88, uid[0..6]] → 8 bytes
    /// - 10-byte UID: [0x88, uid[0..2], 0x88, uid[3..9]] → 12 bytes
    public static func cascadeUID(_ uid: Data) -> Data {
        switch uid.count {
        case 7:
            var result = Data(capacity: 8)
            result.append(0x88)
            result.append(uid)
            return result
        case 10:
            var result = Data(capacity: 12)
            result.append(0x88)
            result.append(uid[uid.startIndex ..< uid.startIndex + 3])
            result.append(0x88)
            result.append(uid[uid.startIndex + 3 ..< uid.startIndex + 10])
            return result
        default:
            return uid
        }
    }

    // MARK: - ATS Parsing

    /// Parse an ATS (Answer To Select) from ISO 14443-4A.
    /// Byte 0 is T0 and indicates whether TA, TB, and TC are present.
    public static func parseATS(_ ats: Data) -> ATSInfo {
        guard !ats.isEmpty else {
            return ATSInfo(fsci: 0, ta: nil, tb: nil, tc: nil, historicalBytes: Data())
        }

        let t0 = ats[ats.startIndex]
        let fsci = t0 & 0x0F
        var offset = ats.startIndex + 1

        let ta: UInt8? = if t0 & 0x10 != 0, offset < ats.endIndex {
            { let v = ats[offset]; offset += 1; return v }()
        } else {
            nil
        }

        let tb: UInt8? = if t0 & 0x20 != 0, offset < ats.endIndex {
            { let v = ats[offset]; offset += 1; return v }()
        } else {
            nil
        }

        let tc: UInt8? = if t0 & 0x40 != 0, offset < ats.endIndex {
            { let v = ats[offset]; offset += 1; return v }()
        } else {
            nil
        }

        let historicalBytes = offset < ats.endIndex ? Data(ats[offset...]) : Data()

        return ATSInfo(fsci: fsci, ta: ta, tb: tb, tc: tc, historicalBytes: historicalBytes)
    }
}

/// Parsed ATS (Answer To Select) information.
public struct ATSInfo: Sendable, Equatable, Codable {
    /// Frame Size for proximity Card Integer (FSCI): the largest frame the card can receive.
    public let fsci: UInt8
    /// TA: data rate capabilities.
    public let ta: UInt8?
    /// TB: Frame Waiting Time Integer (FWI) and Start-up Frame Guard Time Integer (SFGI).
    public let tb: UInt8?
    /// TC: NAD and CID support flags.
    public let tc: UInt8?
    /// Historical bytes from the ATS.
    public let historicalBytes: Data

    public init(fsci: UInt8, ta: UInt8?, tb: UInt8?, tc: UInt8?, historicalBytes: Data) {
        self.fsci = fsci
        self.ta = ta
        self.tb = tb
        self.tc = tc
        self.historicalBytes = historicalBytes
    }

    /// Maximum frame size the card can receive, derived from FSCI.
    public var maxFrameSize: Int {
        switch fsci {
        case 0: 16
        case 1: 24
        case 2: 32
        case 3: 40
        case 4: 48
        case 5: 64
        case 6: 96
        case 7: 128
        case 8: 256
        default: 256
        }
    }
}
