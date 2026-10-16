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
public enum DG2Parser {
    /// Extract the face image data (JPEG or JPEG2000 bytes) from DG2.
    ///
    /// The TLV levels are walked as slices of `data`, so nesting does not copy the
    /// (possibly multi-megabyte) payload once per level; only the extracted image is
    /// copied.
    public static func parse(_ data: Data) throws -> Data {
        let headers = try ASN1Parser.parseTLVHeaders(data)

        // Find outermost DG2 wrapper (0x75)
        guard let dg2Header = headers.first(where: { $0.tag == 0x75 }) else {
            throw NFCError.dataGroupParseFailed("DG2: missing 0x75 wrapper tag")
        }

        // Find biometric data within the hierarchy
        // Search recursively for tag 0x5F2E (primitive) or 0x7F2E (constructed)
        if let imageData = findBiometricData(in: data[dg2Header.valueRange], depth: 0) {
            guard !imageData.isEmpty else {
                throw NFCError.dataGroupParseFailed("DG2: biometric data object is empty")
            }
            return imageData
        }

        throw NFCError.dataGroupParseFailed("DG2: could not find biometric image data (0x5F2E/0x7F2E)")
    }

    /// Maximum TLV nesting depth searched for biometric data, counted from the content
    /// of the `75` wrapper. ICAO 9303-10 §4.7.2 nests the biometric data block three
    /// levels deep (`7F61` → `7F60` → `5F2E`/`7F2E`, depth 2); the cap leaves room for
    /// wrappers such as ISO/IEC 39794-5 data and bounds work on hostile chip data.
    public static let maxSearchDepth = 8

    /// Recursively search for biometric image data in DG2 TLV structure.
    ///
    /// `data` may be a slice; nested levels are searched as slices of it.
    public static func findBiometricData(in data: Data, depth: Int) -> Data? {
        guard depth < maxSearchDepth, let headers = try? ASN1Parser.parseTLVHeaders(data) else { return nil }

        for header in headers {
            // Tag 0x5F2E: primitive biometric data; 0x7F2E: constructed biometric data.
            if header.tag == PassportConstants.DG2Tags.biometricData
                || header.tag == PassportConstants.DG2Tags.biometricDataConstructed
            {
                return extractImage(from: data[header.valueRange])
            }
            // Recurse into constructed nodes
            if header.isConstructed {
                if let found = findBiometricData(in: data[header.valueRange], depth: depth + 1) {
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
    ///
    /// `input` may be a slice; the result is a copy indexed from zero.
    public static func extractImage(from input: Data) -> Data {
        let start = input.startIndex
        let count = input.count
        // An empty or 1-byte biometric data object holds no image signature.
        guard count >= 2 else { return Data(input) }

        func image(from offset: Int) -> Data {
            Data(input[(start + offset)...])
        }

        // Look for JPEG signature (FFD8)
        for i in 0 ..< count - 1 {
            if input[start + i] == 0xFF, input[start + i + 1] == 0xD8 {
                return image(from: i)
            }
        }

        // Look for JPEG2000 signature (0000000C)
        if count > 4 {
            for i in 0 ..< count - 3 {
                if input[start + i] == 0x00, input[start + i + 1] == 0x00,
                   input[start + i + 2] == 0x00, input[start + i + 3] == 0x0C
                {
                    return image(from: i)
                }
            }
        }

        // Look for raw JPEG2000 codestream markers SOC (FF4F) + SIZ (FF51)
        if count > 4 {
            for i in 0 ..< count - 3 {
                if input[start + i] == 0xFF, input[start + i + 1] == 0x4F,
                   input[start + i + 2] == 0xFF, input[start + i + 3] == 0x51
                {
                    return image(from: i)
                }
            }
        }

        // Fallback: return entire data
        return Data(input)
    }
}
