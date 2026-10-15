import Foundation

/// MRZ key generator for BAC authentication.
///
/// Computes the MRZ key from document number, date of birth, and date of expiry,
/// including check digits per ICAO Doc 9303 Part 3.
///
/// Reference: ICAO Doc 9303 Part 3, Section 4.9 (check digit algorithm)
/// https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf
/// Reference: ICAO Doc 9303 Part 11, Section 9.7.1.2 (MRZ key composition)
/// https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
public enum MRZKeyGenerator {
    /// Compute the BAC MRZ key from passport data.
    ///
    /// Format: documentNumber + checkDigit + dateOfBirth + checkDigit + dateOfExpiry + checkDigit
    ///
    /// - Parameters:
    ///   - documentNumber: The document number. Shorter numbers are padded with `<` to
    ///     9 characters; longer TD1 numbers (ICAO 9303-5 §4.2.2 overflow into optional data)
    ///     are used in full, as the BAC/PACE MRZ information requires. Lowercase is uppercased.
    ///   - dateOfBirth: Date of birth in YYMMDD format.
    ///   - dateOfExpiry: Date of expiry in YYMMDD format.
    /// - Returns: The MRZ key string for BAC key derivation.
    public static func computeMRZKey(
        documentNumber: String,
        dateOfBirth: String,
        dateOfExpiry: String
    ) -> String {
        let normalizedDocNumber = documentNumber.uppercased()
        // Pad to 9 characters with `<`; never truncate long document numbers.
        let paddedDocNumber = normalizedDocNumber.count >= 9
            ? normalizedDocNumber
            : normalizedDocNumber + String(repeating: "<", count: 9 - normalizedDocNumber.count)

        let docCheckDigit = checkDigit(paddedDocNumber)
        let dobCheckDigit = checkDigit(dateOfBirth)
        let doeCheckDigit = checkDigit(dateOfExpiry)

        return paddedDocNumber + String(docCheckDigit)
            + dateOfBirth + String(dobCheckDigit)
            + dateOfExpiry + String(doeCheckDigit)
    }

    /// Compute ICAO 9303 check digit.
    ///
    /// Algorithm: For each character, multiply its value by the corresponding
    /// weight (7, 3, 1, repeating), sum all products, return sum mod 10.
    ///
    /// Character values:
    /// - `0`–`9` → 0–9
    /// - `A`–`Z` → 10–35
    /// - `<` → 0
    ///
    /// Lowercase ASCII letters are treated as uppercase. Only ASCII digits count as
    /// digits; any other character (including non-ASCII digits) is valued 0 like `<`.
    public static func checkDigit(_ input: String) -> Character {
        let weights = [7, 3, 1]
        var sum = 0

        for (index, char) in input.uppercased().enumerated() {
            let value: Int = if let ascii = char.asciiValue, ascii >= 0x30, ascii <= 0x39 {
                Int(ascii - 0x30)
            } else if let ascii = char.asciiValue, ascii >= 0x41, ascii <= 0x5A {
                Int(ascii - 0x41) + 10
            } else {
                // `<` and any other filler
                0
            }
            sum += value * weights[index % 3]
        }

        return Character(String(sum % 10))
    }
}
