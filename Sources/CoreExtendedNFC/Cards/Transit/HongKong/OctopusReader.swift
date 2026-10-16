import Foundation

/// Reads balance from Hong Kong Octopus FeliCa transit cards.
///
/// Subclasses must preserve thread safety: any added mutable state must be lock-protected or immutable.
open class OctopusReader: @unchecked Sendable {
    public let transport: any FeliCaTagTransporting
    public let balanceOffset: Int

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
        balanceOffset = OctopusConstants.defaultBalanceRawOffset
    }

    public init(
        transport: any FeliCaTagTransporting,
        balanceOffset: Int
    ) {
        self.transport = transport
        self.balanceOffset = balanceOffset
    }

    open func readBalance() async throws -> TransitBalance {
        NFCLog.info("Octopus balance read start idm=\(NFCLog.payload(transport.identifier))", source: "Octopus")
        try validateSystemCode()

        NFCLog.debug("Octopus request service balance=\(OctopusConstants.balanceServiceCode.hexString)", source: "Octopus")
        let versions = try await transport.requestService(
            nodeCodeList: [OctopusConstants.balanceServiceCode]
        )
        NFCLog.debug("Octopus balance service versions=\(versions.map(\.hexString).joined(separator: ","))", source: "Octopus")
        guard let version = versions.first, version != Data([0xFF, 0xFF]) else {
            // Balance service 0x0117 is missing.
            throw NFCError.tagNotSupported
        }

        let blocks = try await transport.readWithoutEncryption(
            serviceCode: OctopusConstants.balanceServiceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: 0)]
        )
        guard let block = blocks.first, block.count >= 4 else {
            NFCLog.error("Octopus invalid balance block=\(NFCLog.payload(blocks.first ?? Data()))", source: "Octopus")
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }

        let rawValue = Int(Data(block.prefix(4)).uint32BE)
        let balanceCents = Self.balanceCents(rawValue: rawValue, offset: balanceOffset)
        NFCLog.debug(
            "Octopus balance block=\(NFCLog.payload(block)) raw=\(NFCLog.cardValue(rawValue)) offset=\(balanceOffset) cents=\(NFCLog.cardValue(balanceCents))",
            source: "Octopus"
        )
        NFCLog.info("Octopus balance read complete balanceCents=\(NFCLog.cardValue(balanceCents))", source: "Octopus")

        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balanceCents,
            currencyCode: "HKD",
            cardName: "Octopus"
        )
    }

    open class func balanceCents(rawValue: Int, offset: Int = OctopusConstants.defaultBalanceRawOffset) -> Int {
        (rawValue - offset) * 10
    }

    open func validateSystemCode() throws {
        NFCLog.debug("Octopus system code=\(transport.systemCode.hexString) expected=\(OctopusConstants.systemCode.hexString)", source: "Octopus")
        guard transport.systemCode == OctopusConstants.systemCode else {
            // Not an Octopus (0x8008) card.
            throw NFCError.tagNotSupported
        }
    }
}
