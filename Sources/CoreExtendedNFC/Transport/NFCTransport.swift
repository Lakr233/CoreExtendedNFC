import Foundation

/// Common transport interface for CoreNFC-backed tag adapters.
public protocol NFCTagTransport: Sendable {
    /// Send raw bytes, receive raw response bytes.
    func send(_ data: Data) async throws -> Data

    /// Send an ISO 7816 APDU, receive a parsed response.
    func sendAPDU(_ apdu: CommandAPDU) async throws -> ResponseAPDU

    /// Tag identifier (UID).
    var identifier: Data { get }
}

/// ISO 7816 transport capabilities used by pure protocol logic.
public protocol ISO7816TagTransporting: NFCTagTransport {
    /// The AID initially selected by CoreNFC when the tag was discovered.
    var initialAID: String { get }

    /// Send an APDU and automatically follow `GET RESPONSE` chaining.
    func sendAPDUWithChaining(_ apdu: CommandAPDU) async throws -> ResponseAPDU
}

/// FeliCa transport capabilities used by pure protocol logic.
public protocol FeliCaTagTransporting: NFCTagTransport {
    /// System Code reported by the polled tag.
    var systemCode: Data { get }

    /// Read blocks without encryption from one or more services.
    func readWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data]
    ) async throws -> [Data]

    /// Read blocks without encryption from the specified service.
    func readWithoutEncryption(
        serviceCode: Data,
        blockList: [Data]
    ) async throws -> [Data]

    /// Write blocks without encryption to one or more services.
    func writeWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data],
        blockData: [Data]
    ) async throws

    /// Write blocks without encryption to the specified service.
    func writeWithoutEncryption(
        serviceCode: Data,
        blockList: [Data],
        blockData: [Data]
    ) async throws

    /// Query whether service codes exist on the current tag.
    func requestService(nodeCodeList: [Data]) async throws -> [Data]
}

public extension FeliCaTagTransporting {
    func readWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data]
    ) async throws -> [Data] {
        guard let serviceCode = serviceCodeList.onlyElement else {
            throw NFCError.unsupportedOperation(
                "Multi-service FeliCa reads are not supported by this transport"
            )
        }
        return try await readWithoutEncryption(serviceCode: serviceCode, blockList: blockList)
    }

    func writeWithoutEncryption(
        serviceCodeList: [Data],
        blockList: [Data],
        blockData: [Data]
    ) async throws {
        guard let serviceCode = serviceCodeList.onlyElement else {
            throw NFCError.unsupportedOperation(
                "Multi-service FeliCa writes are not supported by this transport"
            )
        }
        try await writeWithoutEncryption(
            serviceCode: serviceCode,
            blockList: blockList,
            blockData: blockData
        )
    }
}

/// ISO 15693 transport capabilities used by pure protocol logic.
public protocol ISO15693TagTransporting: NFCTagTransport {
    /// Manufacturer code reported by the tag.
    var icManufacturerCode: Int { get }

    /// Read a single block.
    func readBlock(_ number: UInt8) async throws -> Data

    /// Write a single block.
    func writeBlock(_ number: UInt8, data: Data) async throws

    /// Extended READ SINGLE BLOCK (ISO/IEC 15693-3 command 0x30, 2-byte block number)
    /// for tags with more than 256 blocks. Not every tag implements it.
    func extendedReadBlock(_ number: UInt16) async throws -> Data

    /// Extended WRITE SINGLE BLOCK (ISO/IEC 15693-3 command 0x31, 2-byte block number).
    func extendedWriteBlock(_ number: UInt16, data: Data) async throws

    /// Read multiple contiguous blocks.
    func readBlocks(range: NSRange) async throws -> [Data]

    /// Query system information for the current tag.
    func getSystemInfo() async throws -> ISO15693SystemInfo

    /// Query lock status for a range of blocks.
    func getBlockSecurityStatus(range: NSRange) async throws -> [Bool]

    /// Write the Application Family Identifier.
    func writeAFI(_ afi: UInt8) async throws

    /// Permanently lock the current AFI value.
    func lockAFI() async throws

    /// Write the Data Storage Format Identifier.
    func writeDSFID(_ dsfid: UInt8) async throws

    /// Permanently lock the current DSFID value.
    func lockDSFID() async throws

    /// Send a manufacturer-specific custom command.
    func customCommand(code: Int, parameters: Data) async throws -> Data

    /// Issue an ISO 15693 challenge step for the selected crypto suite.
    func challenge(cryptoSuiteIdentifier: Int, message: Data) async throws

    /// Authenticate using the selected crypto suite.
    func authenticate(cryptoSuiteIdentifier: Int, message: Data) async throws -> ISO15693SecurityResponse

    /// Update a security key on tags that support ISO 15693 key update.
    func keyUpdate(keyIdentifier: Int, message: Data) async throws -> ISO15693SecurityResponse
}

public extension ISO15693TagTransporting {
    func extendedReadBlock(_: UInt16) async throws -> Data {
        throw NFCError.unsupportedOperation("ISO 15693 extended block reads are not supported by this transport")
    }

    func extendedWriteBlock(_: UInt16, data _: Data) async throws {
        throw NFCError.unsupportedOperation("ISO 15693 extended block writes are not supported by this transport")
    }

    func writeAFI(_: UInt8) async throws {
        throw NFCError.unsupportedOperation("ISO 15693 AFI updates are not supported by this transport")
    }

    func lockAFI() async throws {
        throw NFCError.unsupportedOperation("ISO 15693 AFI locking is not supported by this transport")
    }

    func writeDSFID(_: UInt8) async throws {
        throw NFCError.unsupportedOperation("ISO 15693 DSFID updates are not supported by this transport")
    }

    func lockDSFID() async throws {
        throw NFCError.unsupportedOperation("ISO 15693 DSFID locking is not supported by this transport")
    }

    func customCommand(code _: Int, parameters _: Data) async throws -> Data {
        throw NFCError.unsupportedOperation("ISO 15693 custom commands are not supported by this transport")
    }

    func challenge(cryptoSuiteIdentifier _: Int, message _: Data) async throws {
        throw NFCError.unsupportedOperation("ISO 15693 challenge is not supported by this transport")
    }

    func authenticate(cryptoSuiteIdentifier _: Int, message _: Data) async throws -> ISO15693SecurityResponse {
        throw NFCError.unsupportedOperation("ISO 15693 authentication is not supported by this transport")
    }

    func keyUpdate(keyIdentifier _: Int, message _: Data) async throws -> ISO15693SecurityResponse {
        throw NFCError.unsupportedOperation("ISO 15693 key update is not supported by this transport")
    }
}

private extension Collection {
    var onlyElement: Element? {
        count == 1 ? first : nil
    }
}
