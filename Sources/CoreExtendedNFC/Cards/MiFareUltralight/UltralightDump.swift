import Foundation

/// Full card dump and restore operations for Ultralight/NTAG.
/// Ported from libnfc utils/nfc-mfultralight.c dump/restore logic.
public struct UltralightDump: Sendable {
    public let commands: UltralightCommands

    public init(commands: UltralightCommands) {
        self.commands = commands
    }

    /// Read all pages into a MemoryDump.
    public func dumpAll(cardInfo: CardInfo, map: UltralightMemoryMap) async throws -> MemoryDump {
        var pages: [MemoryDump.Page] = []
        var facts: [MemoryDump.Fact] = []
        var capabilities: [CardCapability] = []
        let lastPlainReadablePage = cardInfo.type == .mifareUltralightC ? UInt8(44) : map.totalPages

        // Read 4 pages at a time using READ command
        var page: UInt8 = 0
        while page < lastPlainReadablePage {
            try Task.checkCancellation()
            let data: Data
            do {
                data = try await commands.readPages(startPage: page)
            } catch let error as NFCError {
                // A NAK (surfaced as a short response) past AUTH0 on a
                // read-protected tag: keep the pages that were readable
                // instead of discarding the whole dump. Ultralight C
                // (AUTH0/AUTH1), Ultralight EV1 and NTAG21x (AUTH0 with
                // ACCESS.PROT = 1) all behave this way.
                if case .invalidResponse = error, !pages.isEmpty {
                    facts.append(.init(key: "Unauthenticated Boundary", value: "Page \(page)"))
                    capabilities = [.authenticationRequired, .partiallyReadable]
                    break
                }
                throw error
            }
            // Each READ returns 4 pages (16 bytes)
            let bytes = [UInt8](data)
            for i in 0 ..< 4 {
                let pageNum = Int(page) + i
                guard pageNum < Int(lastPlainReadablePage) else { break }
                let offset = i * 4
                pages.append(MemoryDump.Page(number: UInt8(pageNum), data: Data(bytes[offset ..< offset + 4])))
            }
            guard page <= UInt8.max - 4 else { break }
            page += 4
        }

        let ndefMessage = NDEFTagMapping.extractType2Message(from: pages)
        facts.insert(contentsOf: [
            .init(key: "Pages", value: "\(pages.count)"),
        ], at: 0)
        if let ndefMessage {
            facts.append(.init(key: "NDEF Bytes", value: "\(ndefMessage.count)"))
        }

        if cardInfo.type == .mifareUltralightC {
            facts.append(.init(key: "Readable Pages", value: "0-43"))
            facts.append(.init(key: "Secret Key Pages", value: "44-47"))

            if capabilities.isEmpty {
                capabilities = [.partiallyReadable]
            }

            if let authConfig = try? parseUltralightCAccessConfiguration(from: pages) {
                facts.append(.init(key: "Protection", value: authConfig.protectionDescription))
                if let firstProtectedPage = authConfig.firstProtectedPage {
                    facts.append(.init(key: "First Protected Page", value: "\(firstProtectedPage)"))
                }
            }
        } else if capabilities.isEmpty {
            capabilities = [.readable]
        }

        return MemoryDump(
            cardInfo: cardInfo,
            pages: pages,
            ndefMessage: ndefMessage,
            facts: facts,
            capabilities: capabilities
        )
    }

    /// Restore user pages from a MemoryDump (skips read-only pages 0-3).
    public func restore(dump: MemoryDump, map: UltralightMemoryMap) async throws {
        for page in dump.pages {
            // Skip manufacturer pages (0-3), they are read-only
            guard page.number >= map.userDataStart else { continue }
            // Skip pages beyond the user data area
            guard page.number <= map.userDataEnd else { continue }
            // Skip lock/config pages during normal restore
            if let configStart = map.configStart, page.number >= configStart { continue }
            if let lockStart = map.dynamicLockStart, page.number == lockStart { continue }

            try await commands.writePage(page.number, data: page.data)
        }
    }

    private func parseUltralightCAccessConfiguration(
        from pages: [MemoryDump.Page]
    ) throws -> UltralightCAccessConfiguration {
        guard
            let auth0Page = pages.first(where: { $0.number == 42 })?.data.first,
            let auth1Page = pages.first(where: { $0.number == 43 })?.data.first
        else {
            throw NFCError.invalidResponse(Data())
        }

        let firstProtectedPage: UInt8? = auth0Page == 0x30 ? nil : auth0Page
        return UltralightCAccessConfiguration(firstProtectedPage: firstProtectedPage, auth1: auth1Page)
    }
}
