import Foundation

/// PIN domains exposed by Japanese My Number card applets.
public enum MyNumberPINType: String, Sendable, Equatable, Codable, CaseIterable {
    /// Digital signature certificate PIN (JPKI).
    case digitalSignature
    /// User authentication certificate PIN (JPKI).
    case userAuthentication
    /// Card-info-input-support PIN.
    case cardInfoInputSupport
    /// Individual number / resident-registry PIN domain.
    case individualNumber
}
