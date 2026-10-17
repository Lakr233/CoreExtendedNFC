import Foundation

/// Full card dump and restore operations for Ultralight/NTAG.
/// Ported from libnfc utils/nfc-mfultralight.c dump/restore logic.
///
/// Subclasses must preserve thread safety: any added mutable state must be
/// lock-protected or immutable.
open class UltralightDump: @unchecked Sendable {
    public let commands: UltralightCommands

    public init(commands: UltralightCommands) {
        self.commands = commands
    }

    /// Read all pages into a MemoryDump.
    open func dumpAll(cardInfo: CardInfo, map: UltralightMemoryMap) async throws -> MemoryDump {
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
        facts.insert(
            contentsOf: [
                .init(key: "Pages", value: "\(pages.count)"),
            ],
            at: 0
        )
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

    /// Read pages `start ..< end` with READ (30h), stopping early at the first page
    /// the tag does not return.
    ///
    /// A NAK (surfaced as a short response) or a missing answer ends the read and
    /// the pages read so far are returned: past the end of memory or a protected
    /// area a Type 2 tag NAKs or stays silent. Session loss and cancellation are
    /// rethrown. `end` is capped at 256, the pages READ can address.
    open func readPagesUntilRejected(from start: Int, to end: Int) async throws -> [MemoryDump.Page] {
        let end = min(end, 256)
        var pages: [MemoryDump.Page] = []
        var page = max(start, 0)
        while page < end {
            try Task.checkCancellation()
            let data: Data
            do {
                data = try await commands.readPages(startPage: UInt8(page))
            } catch where !isSessionTerminating(error) || isMissingTagResponse(error) {
                break
            }
            for index in 0 ..< 4 where page + index < end {
                let offset = data.startIndex + index * 4
                pages.append(MemoryDump.Page(number: UInt8(page + index), data: Data(data[offset ..< offset + 4])))
            }
            page += 4
        }
        return pages
    }

    /// Restore user pages from a MemoryDump.
    ///
    /// Only pages inside the user data area of `map` are written; pages 0-3, the
    /// dynamic lock and the configuration pages are skipped. Every page is
    /// validated before the first write, so a bad dump never leaves the tag
    /// half-restored.
    ///
    /// - Parameters:
    ///   - dump: The dump to restore.
    ///   - map: The target tag's memory map.
    ///   - target: The target tag, when known. Its type must match
    ///     `dump.cardInfo.type`, so a dump is never written onto a different product.
    /// - Throws: ``NFCError/invalidParameter(_:)`` when `map` is not
    ///   ``UltralightMemoryMap/isValid``, a page to restore is not 4 bytes or
    ///   the card types differ. Nothing is written in that case.
    open func restore(dump: MemoryDump, map: UltralightMemoryMap, target: CardInfo? = nil) async throws {
        try map.validate()
        if let target, target.type != dump.cardInfo.type {
            throw NFCError.invalidParameter(
                "The dump is from a \(dump.cardInfo.type.description) but the tag is a \(target.type.description)"
            )
        }
        let writes = dump.pages.filter { Self.isRestorable($0.number, map: map) }
        if let page = writes.first(where: { $0.data.count != 4 }) {
            throw NFCError.invalidParameter("Page \(page.number) holds \(page.data.count) bytes instead of 4")
        }

        for page in writes {
            try Task.checkCancellation()
            try await commands.writePage(page.number, data: page.data, memoryMap: map)
        }
    }

    /// User data pages only: not pages 0-3, the dynamic lock or configuration pages.
    open class func isRestorable(_ page: UInt8, map: UltralightMemoryMap) -> Bool {
        guard map.isUserDataPage(page) else { return false }
        if let configStart = map.configStart, page >= configStart { return false }
        if let lockStart = map.dynamicLockStart, page == lockStart { return false }
        return true
    }

    open func parseUltralightCAccessConfiguration(
        from pages: [MemoryDump.Page]
    ) throws -> UltralightCAccessConfiguration {
        guard
            let auth0Page = pages.first(where: { $0.number == 42 })?.data.first,
            let auth1Page = pages.first(where: { $0.number == 43 })?.data.first
        else {
            throw NFCError.invalidResponse(Data())
        }

        let firstProtectedPage = UltralightCAccessConfiguration.firstProtectedPage(fromAUTH0: auth0Page)
        return UltralightCAccessConfiguration(firstProtectedPage: firstProtectedPage, auth1: auth1Page)
    }
}
