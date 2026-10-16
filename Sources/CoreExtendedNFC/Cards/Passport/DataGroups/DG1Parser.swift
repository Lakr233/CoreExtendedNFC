import Foundation

/// Parser for DG1 (MRZ Data).
///
/// TLV wrapper tag: 0x61
/// MRZ data tag: 0x5F1F
///
/// Structure:
/// ```
/// 61 <len>
///   5F1F <len> <MRZ string bytes>
/// ```
public enum DG1Parser {
    public static func parse(_ data: Data) throws -> MRZData {
        let nodes = try ASN1Parser.parseTLV(data)

        guard let dg1Node = nodes.first(where: { $0.tag == 0x61 }) else {
            throw NFCError.dataGroupParseFailed("DG1: missing 0x61 wrapper tag")
        }

        let children = try dg1Node.children()

        guard let mrzNode = children.first(where: { $0.tag == 0x5F1F }) else {
            throw NFCError.dataGroupParseFailed("DG1: missing 0x5F1F MRZ tag")
        }

        guard let mrzString = String(data: mrzNode.value, encoding: .utf8) else {
            throw NFCError.dataGroupParseFailed("DG1: MRZ data is not valid UTF-8")
        }

        return try MRZData(mrzString: mrzString)
    }
}
