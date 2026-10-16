import Foundation

/// Parser for DG7 (Signature/Usual Mark Image).
///
/// TLV wrapper tag: 0x67
/// Contains digitized signature or usual mark of the holder.
///
/// Structure:
/// ```
/// 67 <len>
///   02 <len> <count>       Number of instances
///   5F43 <len> <image>     Image data (JPEG/JPEG2000)
/// ```
public enum DG7Parser {
    /// Extract signature image bytes from DG7.
    public static func parse(_ data: Data) throws -> Data? {
        let nodes = try ASN1Parser.parseTLV(data)

        guard let dg7Node = nodes.first(where: { $0.tag == 0x67 }) else {
            throw NFCError.dataGroupParseFailed("DG7: missing 0x67 wrapper tag")
        }

        let children = try dg7Node.children()

        // Tag 0x5F43 contains the displayed image
        if let imageNode = children.first(where: { $0.tag == 0x5F43 }) {
            return imageNode.value
        }

        // Recursively search
        if let imageNode = ASN1Parser.findTag(0x5F43, in: children) {
            return imageNode.value
        }

        return nil
    }
}
