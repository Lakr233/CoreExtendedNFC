import Foundation

/// Parser for DG12 (Additional Document Details).
///
/// TLV wrapper tag: 0x6C
///
/// Contains optional document information such as issuing authority,
/// date of issue, endorsements/observations, and tax/exit requirements.
///
/// Tags within DG12:
/// - 0x5F19: Issuing Authority
/// - 0x5F26: Date of Issue (YYYYMMDD)
/// - 0x5F1B: Endorsements/Observations
/// - 0x5F1C: Tax/Exit Requirements
/// - 0x5F55: Date of Personalization (YYYYMMDD)
/// - 0x5F56: Serial Number of Personalization Device
public enum DG12Parser {
    public static let tagMapping: [(UInt, String)] = [
        (0x5F19, "issuingAuthority"),
        (0x5F26, "dateOfIssue"),
        (0x5F1B, "endorsements"),
        (0x5F1C, "taxExitRequirements"),
        (0x5F55, "dateOfPersonalization"),
        (0x5F56, "personalizationDeviceSerial"),
    ]

    public static func parse(_ data: Data) throws -> [String: String] {
        let nodes = try ASN1Parser.parseTLV(data)

        guard let dg12Node = nodes.first(where: { $0.tag == 0x6C }) else {
            throw NFCError.dataGroupParseFailed("DG12: missing 0x6C wrapper tag")
        }

        let children = try dg12Node.children()
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
