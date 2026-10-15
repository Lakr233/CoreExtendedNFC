import Foundation

public extension Data {
    /// Compact hex string: "0A1B2C"
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }

    /// Space-separated hex: "0A 1B 2C"
    var hexDump: String {
        map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    /// Multi-line hex dump with offsets counted from the first byte:
    /// 0000: 0A 1B 2C 3D 4E 5F 60 71
    var hexDumpFormatted: String {
        var lines: [String] = []
        for offset in stride(from: 0, to: count, by: 8) {
            let lower = index(startIndex, offsetBy: offset)
            let upper = index(lower, offsetBy: Swift.min(8, count - offset))
            let hex = self[lower ..< upper].map { String(format: "%02X", $0) }.joined(separator: " ")
            lines.append(String(format: "%04X: ", offset) + hex)
        }
        return lines.joined(separator: "\n")
    }

    /// Initialize from a hex string such as `"0A1B2C"` or `"0A 1B\n2C"`.
    /// Whitespace is ignored; any other non-hex character (including `+`, `-`
    /// or a `0x` prefix) or an odd number of digits returns `nil`.
    init?(hexString: String) {
        var data = Data(capacity: hexString.utf8.count / 2)
        var highNibble: UInt8?

        for scalar in hexString.unicodeScalars {
            if scalar.properties.isWhitespace {
                continue
            }
            let nibble: UInt8
            switch scalar.value {
            case 0x30 ... 0x39: nibble = UInt8(scalar.value - 0x30) // 0-9
            case 0x41 ... 0x46: nibble = UInt8(scalar.value - 0x41 + 10) // A-F
            case 0x61 ... 0x66: nibble = UInt8(scalar.value - 0x61 + 10) // a-f
            default: return nil
            }
            if let high = highNibble {
                data.append(high << 4 | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }

        guard highNibble == nil else { return nil }
        self = data
    }
}
