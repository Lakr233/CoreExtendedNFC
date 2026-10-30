import Foundation

/// Constants shared by the prepaid e-money purses in the FeliCa common area
/// (Rakuten Edy, WAON, nanaco).
///
/// ## References
/// - Common area system code 0xFE00, shared by several issuers on one card
/// - TRETJapanNFCReader RakutenEdy / Waon / Nanaco card item types
/// - Service code layout: little-endian 2 bytes
public enum FeliCaCommonAreaConstants {
    /// FeliCa common area system code. Must be registered in the app's Info.plist
    /// under `com.apple.developer.nfc.readersession.felica.systemcodes`.
    public static let systemCode = Data([0xFE, 0x00])
}

extension FeliCaTagTransporting {
    /// Throw `tagNotSupported` unless the tag was polled with the common area system code and
    /// has `serviceCode`. Each purse has its own balance service, so this check also tells
    /// Edy, WAON, and nanaco apart.
    func requireCommonAreaService(_ serviceCode: Data, source: String) async throws {
        NFCLog.debug("\(source) system code=\(systemCode.hexString) expected=\(FeliCaCommonAreaConstants.systemCode.hexString)", source: source)
        guard systemCode == FeliCaCommonAreaConstants.systemCode else {
            // Not polled with the common area (0xFE00).
            throw NFCError.tagNotSupported
        }

        NFCLog.debug("\(source) request service=\(serviceCode.hexString)", source: source)
        let versions = try await requestService(nodeCodeList: [serviceCode])
        NFCLog.debug("\(source) service versions=\(versions.map(\.hexString).joined(separator: ","))", source: source)
        guard let version = versions.first, version != Data([0xFF, 0xFF]) else {
            // This purse's balance service is missing.
            throw NFCError.tagNotSupported
        }
    }

    /// Read one 16-byte block.
    func readCommonAreaBlock(serviceCode: Data, blockNumber: UInt16 = 0, source: String) async throws -> Data {
        let blocks = try await readWithoutEncryption(
            serviceCode: serviceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: blockNumber)]
        )
        guard let block = blocks.first, block.count == 16 else {
            NFCLog.error("\(source) invalid block service=\(serviceCode.hexString) #\(blockNumber)=\(NFCLog.payload(blocks.first ?? Data()))", source: source)
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }
        NFCLog.debug("\(source) service=\(serviceCode.hexString) block #\(blockNumber)=\(NFCLog.payload(block))", source: source)
        return block
    }

    /// Read one block that the card may refuse: a block-level failure gives nil, while session
    /// loss and cancellation propagate to the caller.
    func readOptionalCommonAreaBlock(serviceCode: Data, blockNumber: UInt16 = 0, source: String) async throws -> Data? {
        do {
            return try await readCommonAreaBlock(serviceCode: serviceCode, blockNumber: blockNumber, source: source)
        } catch where !isSessionTerminating(error) {
            NFCLog.debug("\(source) service=\(serviceCode.hexString) block #\(blockNumber) read stopped: \(error.localizedDescription)", source: source)
            return nil
        }
    }

    /// Read up to `maxBlocks` blocks one at a time. The first block the card refuses ends the
    /// list; session loss and cancellation propagate to the caller.
    func readCommonAreaBlocks(serviceCode: Data, maxBlocks: Int, source: String) async throws -> [Data] {
        var blocks: [Data] = []
        for i in 0 ..< maxBlocks {
            try Task.checkCancellation()
            guard let block = try await readOptionalCommonAreaBlock(serviceCode: serviceCode, blockNumber: UInt16(i), source: source) else {
                break
            }
            blocks.append(block)
        }
        return blocks
    }
}

// MARK: - Dates

extension FeliCaCommonAreaConstants {
    /// Build a Japan Standard Time date, the time zone of every purse timestamp, or nil when a
    /// component is out of range.
    static func jstDate(year: Int, month: Int, day: Int, hour: Int = 0, minute: Int = 0, second: Int = 0) -> Date? {
        guard (1 ... 12).contains(month), (1 ... 31).contains(day),
            (0 ... 23).contains(hour), (0 ... 59).contains(minute), (0 ... 59).contains(second)
        else { return nil }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        components.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return Calendar(identifier: .gregorian).date(from: components)
    }

    /// Decode a 2-byte big-endian date: year(7 bits) month(4 bits) day(5 bits), base year 2000.
    /// Returns nil for an all-zero or out-of-range value.
    static func packedDate(_ bytes: Data) -> Date? {
        guard let components = packedDateComponents(bytes) else { return nil }
        return jstDate(year: components.year, month: components.month, day: components.day)
    }

    /// ``packedDate(_:)`` as a `yyyy-MM-dd` string, for metadata.
    static func packedDateString(_ bytes: Data) -> String? {
        guard let components = packedDateComponents(bytes),
            jstDate(year: components.year, month: components.month, day: components.day) != nil
        else { return nil }
        return String(format: "%04d-%02d-%02d", components.year, components.month, components.day)
    }

    private static func packedDateComponents(_ bytes: Data) -> (year: Int, month: Int, day: Int)? {
        guard bytes.count >= 2 else { return nil }
        let raw = Int(Data(bytes.prefix(2)).uint16BE)
        guard raw != 0 else { return nil }
        return (2000 + (raw >> 9 & 0x7F), raw >> 5 & 0x0F, raw & 0x1F)
    }
}
