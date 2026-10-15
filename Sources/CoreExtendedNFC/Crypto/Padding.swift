import Foundation

/// ISO/IEC 9797-1 Method 2 padding used by ICAO 9303 secure messaging.
/// Reference: ISO/IEC 9797-1:2011, Padding Method 2.
public enum ISO9797Padding {
    /// Append `0x80`, then `0x00` bytes until the result is a multiple of `blockSize`.
    static func pad(_ data: Data, blockSize: Int) -> Data {
        var padded = data
        padded.append(0x80)
        while padded.count % blockSize != 0 {
            padded.append(0x00)
        }
        return padded
    }

    /// Remove ISO/IEC 9797-1 Method 2 padding if present; returns the input unchanged otherwise.
    static func unpad(_ data: Data) -> Data {
        guard let markerIndex = paddingMarkerIndex(data) else {
            return Data(data)
        }
        return Data(data[data.startIndex ..< markerIndex])
    }

    /// Remove ISO/IEC 9797-1 Method 2 padding, throwing when the padding is malformed.
    ///
    /// Secure messaging plaintext must always carry Method 2 padding, so a missing
    /// `0x80` marker or a padding run longer than one block means the cryptogram is corrupt.
    static func strictUnpad(_ data: Data, blockSize: Int) throws -> Data {
        guard !data.isEmpty, data.count % blockSize == 0,
              let markerIndex = paddingMarkerIndex(data),
              data.endIndex - markerIndex <= blockSize
        else {
            throw NFCError.secureMessagingError("Invalid ISO/IEC 9797-1 padding in decrypted data")
        }
        return Data(data[data.startIndex ..< markerIndex])
    }

    /// Index of the trailing `0x80` marker, skipping trailing `0x00` bytes.
    private static func paddingMarkerIndex(_ data: Data) -> Data.Index? {
        var index = data.endIndex
        while index > data.startIndex {
            index -= 1
            switch data[index] {
            case 0x00:
                continue
            case 0x80:
                return index
            default:
                return nil
            }
        }
        return nil
    }
}
