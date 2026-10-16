import Foundation

/// Type 4 tag ISO 7816 command helpers.
public enum Type4Constants {
    /// NDEF Tag Application AID (D2760000850101).
    public static let ndefAID = Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01])
    /// NDEF Tag Application AID of T4T mapping 1.0 (D2760000850100). Mapping 1.0
    /// tags select files by identifier with P2 = 00h instead of 0Ch.
    public static let ndefAIDVersion1 = Data([0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00])
    /// Capability Container file ID.
    public static let ccFileID = Data([0xE1, 0x03])
    /// Default NDEF file ID.
    public static let ndefFileID = Data([0xE1, 0x04])
}
