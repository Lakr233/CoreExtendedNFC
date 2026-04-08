import Foundation

/// My Number card fields that can be requested from the reader.
public enum MyNumberCardItem: String, Sendable, Equatable, Codable, CaseIterable {
    /// Token info from JPKI applet (`EF 0006`).
    case tokenInfo
    /// 12-digit individual number (requires card-info-input-support PIN).
    case individualNumber
}
