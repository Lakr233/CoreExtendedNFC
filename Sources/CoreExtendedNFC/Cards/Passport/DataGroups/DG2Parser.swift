import Foundation

/// Parser for DG2 (Face Image).
///
/// TLV wrapper tag: 0x75
/// Contains facial biometric data per ISO 19794-5.
///
/// Structure (simplified):
/// ```
/// 75 <len>
///   7F61 <len>                          Biometric Info Group Template
///     02 <len> <count>                  Number of instances
///     7F60 <len>                        Biometric Info Template
///       A1 <len>                        Biometric Header Template
///         ...                           Header fields
///       5F2E or 7F2E <len> <image>      Biometric data (JPEG/JPEG2000)
/// ```
enum DG2Parser {
    /// Extract the face image data (JPEG or JPEG2000 bytes) from DG2.
    static func parse(_ data: Data) throws -> Data {
        let nodes = try ASN1Parser.parseTLV(data)

        // Find outermost DG2 wrapper (0x75)
        guard let dg2Node = nodes.first(where: { $0.tag == 0x75 }) else {
            throw NFCError.dataGroupParseFailed("DG2: missing 0x75 wrapper tag")
        }

        // Find biometric data within the hierarchy
        // Search recursively for tag 0x5F2E (primitive) or 0x7F2E (constructed)
        if let imageData = findBiometricData(in: dg2Node.value, depth: 0) {
            guard !imageData.isEmpty else {
                throw NFCError.dataGroupParseFailed("DG2: biometric data object is empty")
            }
            return imageData
        }

        throw NFCError.dataGroupParseFailed("DG2: could not find biometric image data (0x5F2E/0x7F2E)")
    }

    /// Maximum TLV nesting depth searched for biometric data. Real DG2 files nest
    /// about four levels; the cap bounds recursion on hostile chip data.
    static let maxSearchDepth = 32

    /// Recursively search for biometric image data in DG2 TLV structure.
    private static func findBiometricData(in data: Data, depth: Int) -> Data? {
        guard depth < maxSearchDepth, let nodes = try? ASN1Parser.parseTLV(data) else { return nil }

        for node in nodes {
            // Tag 0x5F2E: primitive biometric data
            if node.tag == PassportConstants.DG2Tags.biometricData {
                return extractImage(from: node.value)
            }
            // Tag 0x7F2E: constructed biometric data
            if node.tag == PassportConstants.DG2Tags.biometricDataConstructed {
                return extractImage(from: node.value)
            }
            // Recurse into constructed nodes
            if node.isConstructed {
                if let found = findBiometricData(in: node.value, depth: depth + 1) {
                    return found
                }
            }
        }

        return nil
    }

    /// Extract actual image bytes from biometric data.
    ///
    /// The biometric data begins with an ISO 19794-5 facial record header.
    /// We scan for JPEG (0xFFD8), JP2 boxed JPEG2000 (0x0000000C), or
    /// a raw JPEG2000 codestream (0xFF4FFF51).
    private static func extractImage(from input: Data) -> Data {
        let data = Data(input)
        // An empty or 1-byte biometric data object holds no image signature.
        guard data.count >= 2 else { return data }

        // Look for JPEG signature (FFD8)
        for i in 0 ..< data.count - 1 {
            if data[i] == 0xFF, data[i + 1] == 0xD8 {
                return Data(data[i...])
            }
        }

        // Look for JPEG2000 signature (0000000C)
        if data.count > 4 {
            for i in 0 ..< data.count - 3 {
                if data[i] == 0x00, data[i + 1] == 0x00, data[i + 2] == 0x00, data[i + 3] == 0x0C {
                    return Data(data[i...])
                }
            }
        }

        // Look for raw JPEG2000 codestream markers SOC (FF4F) + SIZ (FF51)
        if data.count > 4 {
            for i in 0 ..< data.count - 3 {
                if data[i] == 0xFF, data[i + 1] == 0x4F, data[i + 2] == 0xFF, data[i + 3] == 0x51 {
                    return Data(data[i...])
                }
            }
        }

        // Fallback: return entire data
        return data
    }
}
