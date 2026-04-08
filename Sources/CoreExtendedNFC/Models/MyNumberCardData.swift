import Foundation

/// Decoded fields read from a Japanese My Number card.
public struct MyNumberCardData: Sendable, Equatable, Codable {
    /// JPKI token text (e.g. `JPKIAPICCTOKEN2`).
    public let tokenInfo: String?
    /// 12-digit individual number.
    public let individualNumber: String?

    public init(tokenInfo: String? = nil, individualNumber: String? = nil) {
        self.tokenInfo = tokenInfo
        self.individualNumber = individualNumber
    }
}
