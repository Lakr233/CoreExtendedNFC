import Foundation

extension Data {
    var hexString: String {
        map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    var compactHexString: String {
        map { String(format: "%02X", $0) }.joined()
    }
}
