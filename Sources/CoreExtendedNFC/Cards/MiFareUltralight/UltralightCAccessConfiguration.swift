import Foundation

/// Access-control bytes stored in Ultralight C pages 42 and 43.
public struct UltralightCAccessConfiguration: Sendable, Equatable {
    /// First page that requires authentication, or `nil` when protection is disabled.
    public let firstProtectedPage: UInt8?
    /// Raw AUTH1 byte.
    public let auth1: UInt8

    public init(firstProtectedPage: UInt8?, auth1: UInt8) {
        self.firstProtectedPage = firstProtectedPage
        self.auth1 = auth1
    }

    /// Whether authentication is required for writes in the protected range.
    public var requiresAuthenticationForWrites: Bool {
        firstProtectedPage != nil
    }

    /// Whether authentication is required for reads in the protected range.
    ///
    /// AUTH1 bit 0 (MF0ICU2 §7.5.8, Table 12): `1b` restricts writes only and
    /// allows reads without authentication; `0b` restricts reads and writes.
    public var requiresAuthenticationForReads: Bool {
        firstProtectedPage != nil && (auth1 & 0x01) == 0x00
    }

    /// The first protected page encoded by an AUTH0 byte, or `nil` when
    /// protection is disabled.
    ///
    /// Valid AUTH0 values are 03h–30h (MF0ICU2 §7.5.8); 30h disables protection,
    /// and any larger value lies past the last page (2Fh), so nothing is protected.
    public static func firstProtectedPage(fromAUTH0 auth0: UInt8) -> UInt8? {
        auth0 >= 0x30 ? nil : auth0
    }

    /// Human-readable description of the protection mode.
    public var protectionDescription: String {
        guard firstProtectedPage != nil else {
            return "Disabled"
        }
        return requiresAuthenticationForReads ? "Read and write" : "Write-only"
    }
}
