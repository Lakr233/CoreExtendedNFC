import Foundation

/// Routes raw DataGroup bytes to the appropriate parser.
public enum DataGroupParser {
    /// Parse the contents of a data group.
    ///
    /// - Parameters:
    ///   - id: Which data group this data represents.
    ///   - data: The raw bytes read from the chip (including TLV wrapper).
    /// - Returns: Parsed result or raw data passthrough for unimplemented groups.
    public static func parseCOM(_ data: Data) throws -> (ldsVersion: String, unicodeVersion: String, dataGroups: [DataGroupId]) {
        try COMParser.parse(data)
    }

    public static func parseDG1(_ data: Data) throws -> MRZData {
        try DG1Parser.parse(data)
    }

    public static func parseDG2(_ data: Data) throws -> Data {
        try DG2Parser.parse(data)
    }

    public static func parseDG7(_ data: Data) throws -> Data? {
        try DG7Parser.parse(data)
    }

    public static func parseDG11(_ data: Data) throws -> [String: String] {
        try DG11Parser.parse(data)
    }

    public static func parseDG12(_ data: Data) throws -> [String: String] {
        try DG12Parser.parse(data)
    }

    public static func parseDG14(_ data: Data) throws -> SecurityInfos {
        try DG14Parser.parse(data)
    }

    public static func parseDG15(_ data: Data) throws -> ActiveAuthenticationPublicKey {
        try DG15Parser.parse(data)
    }

    public static func parseSOD(_ data: Data) throws -> SODContent {
        try SODParser.parse(data)
    }
}
