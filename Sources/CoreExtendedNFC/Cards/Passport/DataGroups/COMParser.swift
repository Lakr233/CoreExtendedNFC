import Foundation

/// Parser for COM (Common Data) — EF.COM.
///
/// Contains LDS version, Unicode version, and list of available data groups.
/// TLV wrapper tag: 0x60
///
/// Structure:
/// ```
/// 60 <len>
///   5F01 <len> <LDS version>      (e.g., "0107")
///   5F36 <len> <Unicode version>   (e.g., "040000")
///   5C   <len> <DG tag list>       (e.g., 61 75 = DG1, DG2)
/// ```
public enum COMParser {
    public static func parse(_ data: Data) throws -> (ldsVersion: String, unicodeVersion: String, dataGroups: [DataGroupId]) {
        let nodes = try ASN1Parser.parseTLV(data)

        guard let comNode = nodes.first(where: { $0.tag == 0x60 }) else {
            throw NFCError.dataGroupParseFailed("COM: missing 0x60 wrapper tag")
        }

        let children = try comNode.children()

        // LDS version: tag 0x5F01
        var ldsVersion = ""
        if let ldsNode = children.first(where: { $0.tag == 0x5F01 }) {
            ldsVersion = String(data: ldsNode.value, encoding: .utf8) ?? ldsNode.value.map { String(format: "%02X", $0) }.joined()
        }

        // Unicode version: tag 0x5F36
        var unicodeVersion = ""
        if let uniNode = children.first(where: { $0.tag == 0x5F36 }) {
            unicodeVersion = String(data: uniNode.value, encoding: .utf8) ?? uniNode.value.map { String(format: "%02X", $0) }.joined()
        }

        // Data group tag list: tag 0x5C
        var dataGroups: [DataGroupId] = []
        if let dgListNode = children.first(where: { $0.tag == 0x5C }) {
            for byte in dgListNode.value {
                if let dgId = Self.tagToDataGroupId(UInt(byte)) {
                    dataGroups.append(dgId)
                }
            }
        }

        return (ldsVersion, unicodeVersion, dataGroups)
    }

    public static func tagToDataGroupId(_ tag: UInt) -> DataGroupId? {
        for dgId in DataGroupId.allCases {
            if dgId.tlvTag == tag {
                return dgId
            }
        }
        return nil
    }
}
