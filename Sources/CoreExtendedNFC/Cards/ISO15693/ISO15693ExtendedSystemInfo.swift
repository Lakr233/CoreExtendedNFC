import Foundation

/// ISO/IEC 15693-3:2019 EXTENDED GET SYSTEM INFORMATION (3Bh): request parameters,
/// response parser and the rule for combining it with GET SYSTEM INFORMATION (2Bh).
///
/// GET SYSTEM INFORMATION reports the block count in one byte (value − 1), so it
/// cannot describe more than 256 blocks; a larger tag (such as the ST25DV64K with
/// 2048 blocks) either reports 256 blocks or leaves the memory size out. EXTENDED
/// GET SYSTEM INFORMATION reports the block count in two bytes.
public enum ISO15693ExtendedSystemInfo {
    /// Command code of EXTENDED GET SYSTEM INFORMATION.
    public static let commandCode: UInt8 = 0x3B

    /// Info flags (parameter request field) asking only for the VICC memory size (b3).
    public static let memorySizeRequest: UInt8 = 0x04

    /// Response Info flags bits (ISO/IEC 15693-3:2019, Extended Get System Information).
    public enum InfoFlag {
        public static let dsfid: UInt8 = 0x01
        public static let afi: UInt8 = 0x02
        public static let memorySize: UInt8 = 0x04
        public static let icReference: UInt8 = 0x08
        /// MOI: 2-byte block addressing. Carries no field.
        public static let moi: UInt8 = 0x10
        public static let commandList: UInt8 = 0x20
        public static let csiInformation: UInt8 = 0x40
        /// Info flag field is extended to further bytes, which this parser does not know.
        public static let extendedInfoFlags: UInt8 = 0x80
    }

    /// Parse the response payload that follows the response Flags byte (CoreNFC's
    /// `sendRequest` returns the Flags byte separately).
    ///
    /// Layout: Info flags (1 byte), UID (8 bytes, as transmitted, least significant
    /// byte first), then, each only when its Info flag is set: DSFID (1), AFI (1),
    /// memory size (3: number of blocks, 2 bytes least significant first, value − 1;
    /// block size, b5–b1, value − 1), IC reference (1). The VICC command list and
    /// CSI information that may follow are not needed and are ignored.
    ///
    /// Fields that are absent are reported as in ``ISO15693SystemInfo``: `nil` for
    /// DSFID / AFI / IC reference and `-1` for the memory size.
    ///
    /// - Throws: ``NFCError/invalidResponse(_:)`` when the payload is shorter than its
    ///   Info flags announce, or when the Info flag field is extended (b8), whose
    ///   layout this parser does not know.
    public static func parse(_ payload: Data) throws -> ISO15693SystemInfo {
        let bytes = [UInt8](payload)
        guard let infoFlags = bytes.first, infoFlags & InfoFlag.extendedInfoFlags == 0 else {
            throw NFCError.invalidResponse(payload)
        }
        var offset = 1
        func take(_ count: Int) throws -> ArraySlice<UInt8> {
            guard offset + count <= bytes.count else { throw NFCError.invalidResponse(payload) }
            defer { offset += count }
            return bytes[offset ..< offset + count]
        }

        let uid = try Data(take(8))
        let dsfid: UInt8? = try infoFlags & InfoFlag.dsfid != 0 ? take(1).first : nil
        let afi: UInt8? = try infoFlags & InfoFlag.afi != 0 ? take(1).first : nil
        var blockCount = -1
        var blockSize = -1
        if infoFlags & InfoFlag.memorySize != 0 {
            let memory = try Array(take(3))
            blockCount = (Int(memory[0]) | Int(memory[1]) << 8) + 1
            blockSize = Int(memory[2] & 0x1F) + 1
        }
        let icReference: UInt8? = try infoFlags & InfoFlag.icReference != 0 ? take(1).first : nil

        return ISO15693SystemInfo(
            uid: uid,
            dsfid: dsfid,
            afi: afi,
            blockSize: blockSize,
            blockCount: blockCount,
            icReference: icReference
        )
    }

    /// Whether GET SYSTEM INFORMATION may have under-reported the memory: it gave
    /// no memory size, or the 256 blocks that are its one-byte maximum.
    public static func needsExtendedQuery(_ standard: ISO15693SystemInfo) -> Bool {
        standard.blockCount <= 0
            || standard.blockSize <= 0
            || standard.blockCount == ISO15693Reader.singleByteAddressableBlocks
    }

    /// Combine GET SYSTEM INFORMATION with EXTENDED GET SYSTEM INFORMATION.
    ///
    /// The extended memory size is taken only when it is complete and consistent:
    /// when the standard answer reported a size, the extended one must have the same
    /// block size and at least as many blocks. Otherwise `standard` is returned
    /// unchanged. UID, DSFID, AFI and IC reference come from `standard`, and from
    /// `extended` only where `standard` lacks them.
    public static func merge(
        standard: ISO15693SystemInfo,
        extended: ISO15693SystemInfo
    ) -> ISO15693SystemInfo {
        guard extended.blockCount > 0, extended.blockSize > 0 else { return standard }
        if standard.blockCount > 0, standard.blockSize > 0 {
            guard extended.blockSize == standard.blockSize,
                  extended.blockCount >= standard.blockCount
            else { return standard }
        }
        return ISO15693SystemInfo(
            uid: standard.uid.isEmpty ? extended.uid : standard.uid,
            dsfid: standard.dsfid ?? extended.dsfid,
            afi: standard.afi ?? extended.afi,
            blockSize: extended.blockSize,
            blockCount: extended.blockCount,
            icReference: standard.icReference ?? extended.icReference
        )
    }
}
