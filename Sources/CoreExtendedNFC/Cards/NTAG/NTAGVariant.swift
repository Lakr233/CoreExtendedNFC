import Foundation

/// NTAG variant detection from GET_VERSION response.
/// NTAG uses the same GET_VERSION (0x60) as Ultralight EV1.
/// Detection is handled by `UltralightVersionResponse.cardType`.
///
/// NTAG memory configurations:
/// - NTAG213: 45 pages (180 bytes), user pages 4-39, config 41-44
/// - NTAG215: 135 pages (540 bytes), user pages 4-129, config 131-134
/// - NTAG216: 231 pages (924 bytes), user pages 4-225, config 227-230
public enum NTAGVariant: Sendable {
    /// Detect NTAG variant from GET_VERSION, returning refined card type.
    public static func detect(from version: UltralightVersionResponse) -> CardType {
        version.cardType
    }
}
