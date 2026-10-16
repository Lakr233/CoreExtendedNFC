import Foundation

/// FeliCa command operations using CoreNFC's FeliCa tag API.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class FeliCaCommands: @unchecked Sendable {
    public struct ServiceProbe: Sendable, Equatable {
        public let serviceCode: Data
        public let label: String
        public let keyVersion: Data

        public init(serviceCode: Data, label: String, keyVersion: Data) {
            self.serviceCode = serviceCode
            self.label = label
            self.keyVersion = keyVersion
        }
    }

    /// Outcome of reading one block of one service in a shared Read Without Encryption.
    public enum ServiceReadResult: Sendable, Equatable {
        /// The service returned this block.
        case block(Data)
        /// The service has no more readable blocks (or refused the read).
        case stop
    }

    public struct ServiceSnapshot: Sendable, Equatable {
        public let serviceCode: Data
        public let label: String
        public let blocks: [Data]

        public init(serviceCode: Data, label: String, blocks: [Data]) {
            self.serviceCode = serviceCode
            self.label = label
            self.blocks = blocks
        }

        public var payload: Data {
            blocks.reduce(into: Data()) { partial, block in
                partial.append(block)
            }
        }
    }

    public let transport: any FeliCaTagTransporting

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
    }

    open func probeCommonServices(maxServiceIndex: Int = 15) async throws -> [ServiceProbe] {
        let candidates = Self.commonServiceCodes(maxServiceIndex: maxServiceIndex)
        var probes: [ServiceProbe] = []

        for chunk in candidates.chunked(into: 32) {
            let versions = try await transport.requestService(nodeCodeList: chunk.map(\.serviceCode))
            guard versions.count == chunk.count else {
                throw NFCError.invalidResponse(Data(versions.joined()))
            }

            for (candidate, version) in zip(chunk, versions) where version != Self.unavailableServiceVersion {
                probes.append(
                    ServiceProbe(
                        serviceCode: candidate.serviceCode,
                        label: candidate.label,
                        keyVersion: version
                    )
                )
            }
        }

        return probes
    }

    open func readPlainServices(
        _ services: [ServiceProbe],
        maxBlocksPerService: Int = 4,
        excluding excludedServiceCodes: Set<Data> = []
    ) async throws -> [ServiceSnapshot] {
        guard maxBlocksPerService > 0 else { return [] }

        let orderedServices = services.filter { !excludedServiceCodes.contains($0.serviceCode) }
        var collectedBlocks: [Data: [Data]] = [:]
        var activeServices = orderedServices

        for blockNumber in 0 ..< maxBlocksPerService where !activeServices.isEmpty {
            try Task.checkCancellation()
            let readResults = try await readSharedBlock(
                across: activeServices,
                blockNumber: UInt16(blockNumber)
            )
            activeServices = activeServices.filter { service in
                switch readResults[service.serviceCode] {
                case let .block(data):
                    collectedBlocks[service.serviceCode, default: []].append(data)
                    return true
                case .stop, .none:
                    return false
                }
            }
        }

        return orderedServices.compactMap { service in
            guard let blocks = collectedBlocks[service.serviceCode], !blocks.isEmpty else {
                return nil
            }
            return ServiceSnapshot(
                serviceCode: service.serviceCode,
                label: service.label,
                blocks: blocks
            )
        }
    }

    open class func commonServiceCodes(maxServiceIndex: Int = 15) -> [(serviceCode: Data, label: String)] {
        // Service numbers are 10 bits wide (service code = number << 6 | attribute).
        let cappedMaxIndex = min(max(0, maxServiceIndex), 0x3FF)
        var candidates: [(serviceCode: Data, label: String)] = [
            (FeliCaType3Reader.readServiceCode, "NDEF Read Service"),
            (FeliCaType3Reader.writeServiceCode, "NDEF Write Service"),
        ]

        for serviceIndex in 0 ... cappedMaxIndex {
            let serviceNumber = UInt16(serviceIndex)
            for serviceType in Self.probeServiceTypes {
                let code = (serviceNumber << 6) | UInt16(serviceType.accessBits)
                let encoded = encodeServiceCode(code)

                if candidates.contains(where: { $0.serviceCode == encoded }) {
                    continue
                }

                let label = "\(serviceType.displayName) #\(serviceIndex)"
                candidates.append((encoded, label))
            }
        }

        return candidates
    }

    /// Read Without Encryption accepts at most 16 services per command, and the
    /// block list element addresses a service with a 4-bit index.
    public static let maxServicesPerRead = 16

    open func readSharedBlock(
        across services: [ServiceProbe],
        blockNumber: UInt16
    ) async throws -> [Data: ServiceReadResult] {
        guard !services.isEmpty else { return [:] }

        // Larger lists would alias service indexes 16+ onto 0-15 via `& 0x0F`.
        if services.count > Self.maxServicesPerRead {
            var merged: [Data: ServiceReadResult] = [:]
            for chunk in services.chunked(into: Self.maxServicesPerRead) {
                for (serviceCode, result) in try await readSharedBlock(across: chunk, blockNumber: blockNumber) {
                    merged[serviceCode] = result
                }
            }
            return merged
        }

        let serviceCodeList = services.map(\.serviceCode)
        let blockList = services.enumerated().map { serviceIndex, _ in
            FeliCaFrame.blockListElement(
                blockNumber: blockNumber,
                serviceIndex: UInt8(serviceIndex)
            )
        }

        do {
            let response = try await transport.readWithoutEncryption(
                serviceCodeList: serviceCodeList,
                blockList: blockList
            )
            guard response.count == services.count else {
                throw NFCError.invalidResponse(Data(response.joined()))
            }

            var results: [Data: ServiceReadResult] = [:]
            for (service, block) in zip(services, response) {
                guard block.count == FeliCaMemory.blockSize else {
                    throw NFCError.invalidResponse(block)
                }
                results[service.serviceCode] = .block(block)
            }
            return results
        } catch {
            // Losing the tag or the session is not a per-service failure;
            // bisecting would only turn it into a silent empty probe.
            if isSessionTerminating(error) { throw error }
            guard services.count > 1 else {
                return [services[0].serviceCode: .stop]
            }

            let midpoint = services.count / 2
            let left = Array(services.prefix(midpoint))
            let right = Array(services.dropFirst(midpoint))
            var merged = try await readSharedBlock(across: left, blockNumber: blockNumber)
            for (serviceCode, result) in try await readSharedBlock(across: right, blockNumber: blockNumber) {
                merged[serviceCode] = result
            }
            return merged
        }
    }

    public static let unavailableServiceVersion = Data([0xFF, 0xFF])

    public static let probeServiceTypes: [FeliCaMemory.ServiceType] = [
        .randomReadWrite,
        .randomReadOnly,
        .cyclicReadWrite,
        .cyclicReadOnly,
    ]

    public static func encodeServiceCode(_ code: UInt16) -> Data {
        Data([
            UInt8(truncatingIfNeeded: code),
            UInt8(truncatingIfNeeded: code >> 8),
        ])
    }
}

public extension FeliCaMemory.ServiceType {
    /// Human-readable service type name used for probe labels.
    var displayName: String {
        switch self {
        case .randomReadOnly:
            "Random Read-Only Service"
        case .randomReadWrite:
            "Random Read-Write Service"
        case .cyclicReadOnly:
            "Cyclic Read-Only Service"
        case .cyclicReadWrite:
            "Cyclic Read-Write Service"
        case .purseDirectAccess:
            "Purse Direct Access Service"
        case .purseCashback:
            "Purse Cashback Service"
        }
    }
}

private extension Array {
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0, !isEmpty else { return isEmpty ? [] : [self] }

        var result: [[Element]] = []
        var index = startIndex
        while index < endIndex {
            let nextIndex = self.index(index, offsetBy: size, limitedBy: endIndex) ?? endIndex
            result.append(Array(self[index ..< nextIndex]))
            index = nextIndex
        }
        return result
    }
}
