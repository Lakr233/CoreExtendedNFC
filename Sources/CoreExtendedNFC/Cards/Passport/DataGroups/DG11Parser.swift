import Foundation

/// Parser for DG11 (Additional Personal Details).
///
/// TLV wrapper tag: 0x6B
///
/// Contains optional personal information such as full name in national characters,
/// other names, place of birth, address, telephone, profession, etc.
///
/// Tags within DG11:
/// - 0x5F0E: Full Name
/// - 0x5F0F: Other Name(s)
/// - 0x5F10: Personal Number
/// - 0x5F2B: Full Date of Birth (YYYYMMDD)
/// - 0x5F11: Place of Birth
/// - 0x5F42: Address
/// - 0x5F12: Telephone
/// - 0x5F13: Profession
/// - 0x5F14: Title
/// - 0x5F15: Personal Summary
/// - 0x5F16: Proof of Citizenship (image)
/// - 0x5F17: Other Travel Document Numbers
/// - 0x5F18: Custody Information
public enum DG11Parser {
    public static let tagMapping: [(UInt, String)] = [
        (0x5F0E, "fullName"),
        (0x5F0F, "otherNames"),
        (0x5F10, "personalNumber"),
        (0x5F2B, "dateOfBirth"),
        (0x5F11, "placeOfBirth"),
        (0x5F42, "address"),
        (0x5F12, "telephone"),
        (0x5F13, "profession"),
        (0x5F14, "title"),
        (0x5F15, "personalSummary"),
        (0x5F17, "otherTravelDocNumbers"),
        (0x5F18, "custodyInfo"),
    ]

    public static func parse(_ data: Data) throws -> [String: String] {
        let nodes = try ASN1Parser.parseTLV(data)

        guard let dg11Node = nodes.first(where: { $0.tag == 0x6B }) else {
            throw NFCError.dataGroupParseFailed("DG11: missing 0x6B wrapper tag")
        }

        let children = try dg11Node.children()
        var result: [String: String] = [:]

        for (tag, key) in tagMapping {
            if let node = children.first(where: { $0.tag == tag }) {
                if let str = String(data: node.value, encoding: .utf8) {
                    result[key] = str
                }
            }
        }

        return result
    }
}
