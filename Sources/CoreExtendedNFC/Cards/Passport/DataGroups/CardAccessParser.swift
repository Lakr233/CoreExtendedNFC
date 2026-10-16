import Foundation

/// Parser for EF.CardAccess security information.
///
/// EF.CardAccess lives under the master file, outside the eMRTD application, and
/// carries PACE-related SecurityInfo objects when the chip advertises PACE.
public enum CardAccessParser {
    public static let fileID = Data([0x01, 0x1C])

    public static func parse(_ data: Data) throws -> SecurityInfos {
        try DG14Parser.parseSecurityInfos(data, wrapperTag: nil)
    }
}
