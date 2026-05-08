import Foundation

/// Reads balance from Hong Kong Octopus FeliCa transit cards.
public struct OctopusReader: Sendable {
    let transport: any FeliCaTagTransporting
    let balanceOffset: Int

    public init(transport: any FeliCaTagTransporting) {
        self.transport = transport
        balanceOffset = OctopusConstants.defaultBalanceRawOffset
    }

    public init(
        transport: any FeliCaTagTransporting,
        cardIssueDate: Date,
    ) {
        self.transport = transport
        balanceOffset = OctopusConstants.balanceRawOffset(cardIssuedAt: cardIssueDate)
    }

    public init(
        transport: any FeliCaTagTransporting,
        balanceOffset: Int,
    ) {
        self.transport = transport
        self.balanceOffset = balanceOffset
    }

    public func readBalance() async throws -> TransitBalance {
        NFCLog.info("Octopus balance read start idm=\(transport.identifier.hexString)", source: "Octopus")
        try validateSystemCode()

        NFCLog.debug("Octopus request service balance=\(OctopusConstants.balanceServiceCode.hexString)", source: "Octopus")
        let versions = try await transport.requestService(
            nodeCodeList: [OctopusConstants.balanceServiceCode],
        )
        NFCLog.debug("Octopus balance service versions=\(versions.map(\.hexString).joined(separator: ","))", source: "Octopus")
        guard let version = versions.first, version != Data([0xFF, 0xFF]) else {
            throw NFCError.unsupportedOperation("Octopus balance service 0x0117 is unavailable on this card")
        }

        let blocks = try await transport.readWithoutEncryption(
            serviceCode: OctopusConstants.balanceServiceCode,
            blockList: [FeliCaFrame.blockListElement(blockNumber: 0)],
        )
        guard let block = blocks.first, block.count >= 4 else {
            NFCLog.error("Octopus invalid balance block=\((blocks.first ?? Data()).hexString)", source: "Octopus")
            throw NFCError.invalidResponse(blocks.first ?? Data())
        }

        let rawValue = Int(Data(block.prefix(4)).uint32BE)
        let balanceCents = Self.balanceCents(rawValue: rawValue, offset: balanceOffset)
        NFCLog.debug(
            "Octopus balance block=\(block.hexString) raw=\(rawValue) offset=\(balanceOffset) cents=\(balanceCents)",
            source: "Octopus",
        )
        NFCLog.info("Octopus balance read complete balanceCents=\(balanceCents)", source: "Octopus")

        return TransitBalance(
            serialNumber: transport.identifier.hexString,
            balanceRaw: balanceCents,
            currencyCode: "HKD",
            cardName: "Octopus",
        )
    }

    static func balanceCents(rawValue: Int, offset: Int = OctopusConstants.defaultBalanceRawOffset) -> Int {
        (rawValue - offset) * 10
    }

    private func validateSystemCode() throws {
        NFCLog.debug("Octopus system code=\(transport.systemCode.hexString) expected=\(OctopusConstants.systemCode.hexString)", source: "Octopus")
        guard transport.systemCode == OctopusConstants.systemCode else {
            throw NFCError.unsupportedOperation(
                "Expected FeliCa system code 0x8008 (Octopus), got \(transport.systemCode.hexString)",
            )
        }
    }
}
