import Foundation

/// Parsed MRZ (Machine Readable Zone) data from DG1.
///
/// Supports the three ICAO 9303 formats:
/// - TD1: 3 lines × 30 characters (ID cards)
/// - TD2: 2 lines × 36 characters (visas, some ID cards)
/// - TD3: 2 lines × 44 characters (passports)
///
/// Reference: ICAO Doc 9303 Part 3, Sections 4.2-4.4
/// https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
/// Cross-ref: JMRTD MRZInfo.java
/// https://github.com/jmrtd/jmrtd/blob/master/jmrtd/src/main/java/org/jmrtd/lds/icao/MRZInfo.java
public struct MRZData: Sendable, Equatable, Codable {
    /// Document format detected from MRZ string length.
    public enum DocumentFormat: String, Sendable, Codable {
        case td1 // 3×30 = 90 chars
        case td2 // 2×36 = 72 chars
        case td3 // 2×44 = 88 chars
    }

    public let format: DocumentFormat
    public let documentCode: String
    public let issuingState: String
    public let documentNumber: String
    public let dateOfBirth: String
    public let sex: String
    public let dateOfExpiry: String
    public let nationality: String
    public let lastName: String
    public let firstName: String
    public let optionalData1: String
    public let optionalData2: String
    public let mrzString: String

    /// Parses a complete MRZ string with line breaks removed.
    /// - Parameter mrzString: The complete MRZ string (all lines concatenated, no newlines).
    public init(mrzString: String) throws {
        self.mrzString = mrzString
        let chars = Array(mrzString)

        switch chars.count {
        case 90: // TD1: 3 lines × 30
            format = .td1
            documentCode = Self.clean(String(chars[0 ..< 2]))
            issuingState = Self.clean(String(chars[2 ..< 5]))
            documentNumber = Self.clean(String(chars[5 ..< 14]))
            optionalData1 = Self.clean(String(chars[15 ..< 30]))
            dateOfBirth = String(chars[30 ..< 36])
            sex = Self.clean(String(chars[37 ..< 38]))
            dateOfExpiry = String(chars[38 ..< 44])
            nationality = Self.clean(String(chars[45 ..< 48]))
            optionalData2 = Self.clean(String(chars[48 ..< 59]))
            let nameLine = String(chars[60 ..< 90])
            (lastName, firstName) = Self.parseNames(nameLine)

        case 72: // TD2: 2 lines × 36
            format = .td2
            documentCode = Self.clean(String(chars[0 ..< 2]))
            issuingState = Self.clean(String(chars[2 ..< 5]))
            let nameLine = String(chars[5 ..< 36])
            (lastName, firstName) = Self.parseNames(nameLine)
            documentNumber = Self.clean(String(chars[36 ..< 45]))
            nationality = Self.clean(String(chars[46 ..< 49]))
            dateOfBirth = String(chars[49 ..< 55])
            sex = Self.clean(String(chars[56 ..< 57]))
            dateOfExpiry = String(chars[57 ..< 63])
            optionalData1 = Self.clean(String(chars[64 ..< 71]))
            optionalData2 = ""

        case 88: // TD3: 2 lines × 44
            format = .td3
            documentCode = Self.clean(String(chars[0 ..< 2]))
            issuingState = Self.clean(String(chars[2 ..< 5]))
            let nameLine = String(chars[5 ..< 44])
            (lastName, firstName) = Self.parseNames(nameLine)
            documentNumber = Self.clean(String(chars[44 ..< 53]))
            nationality = Self.clean(String(chars[54 ..< 57]))
            dateOfBirth = String(chars[57 ..< 63])
            sex = Self.clean(String(chars[64 ..< 65]))
            dateOfExpiry = String(chars[65 ..< 71])
            optionalData1 = Self.clean(String(chars[72 ..< 86]))
            optionalData2 = ""

        default:
            throw NFCError.dataGroupParseFailed("Invalid MRZ length: \(chars.count) (expected 88, 72, or 90)")
        }
    }

    // MARK: - Private

    /// Replaces filler characters and trims surrounding whitespace.
    public static func clean(_ str: String) -> String {
        str.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces)
    }

    /// Splits an MRZ name field into last and first names.
    public static func parseNames(_ nameLine: String) -> (String, String) {
        let components = nameLine.components(separatedBy: "<<")
        guard components.count >= 2 else {
            return (clean(nameLine), "")
        }

        let lastName = components[0].replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces)
        let firstNameRaw = components.dropFirst().joined(separator: " ")
        let firstName = firstNameRaw.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces)
        return (lastName, firstName)
    }
}
