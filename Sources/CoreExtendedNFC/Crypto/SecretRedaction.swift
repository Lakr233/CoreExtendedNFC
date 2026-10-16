import Foundation

/// Redacted printing for types that hold session keys or authentication randoms.
///
/// `print`, string interpolation, `dump` and the debugger's summary all go through
/// `description`, `debugDescription` or the type's mirror. Each of these shows only
/// non-secret fields and key lengths, so session keys never reach a log or a crash
/// report by accident. The stored properties stay readable for callers that need them.
enum SecretRedaction {
    /// Placeholder for a secret byte string: its length, never its bytes.
    static func redacted(_ data: Data) -> String {
        "<redacted \(data.count) bytes>"
    }
}

extension DESFireAuthenticationSession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "DESFireAuthenticationSession(scheme: \(scheme.rawValue), keyNumber: \(keyNumber), "
            + "sessionENCKey: \(SecretRedaction.redacted(sessionENCKey)), "
            + "sessionMACKey: \(SecretRedaction.redacted(sessionMACKey)), "
            + "commandCounter: \(commandCounter))"
    }

    public var debugDescription: String {
        description
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "scheme": scheme.rawValue,
            "keyNumber": keyNumber,
            "sessionENCKey": SecretRedaction.redacted(sessionENCKey),
            "sessionMACKey": SecretRedaction.redacted(sessionMACKey),
            "commandCounter": commandCounter,
        ], displayStyle: .struct)
    }
}

extension UltralightCAuthenticationSession: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "UltralightCAuthenticationSession(randomA: \(SecretRedaction.redacted(randomA)), "
            + "randomB: \(SecretRedaction.redacted(randomB)))"
    }

    public var debugDescription: String {
        description
    }

    public var customMirror: Mirror {
        Mirror(self, children: [
            "randomA": SecretRedaction.redacted(randomA),
            "randomB": SecretRedaction.redacted(randomB),
        ], displayStyle: .struct)
    }
}
