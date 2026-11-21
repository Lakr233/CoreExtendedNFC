// Dump summaries count pages, bytes and records in the singular or plural form
// of the language they are shown in.
@testable import CoreExtendedNFC
import Foundation
import Testing

struct DumpSummaryTextTests {
    private func ultralightDump(pageCount: Int, ndef: NDEFMessage? = .text("Hi")) -> MemoryDump {
        MemoryDump(
            cardInfo: CardInfo(type: .mifareUltralight, uid: Data([0x04, 0xA2, 0x3B, 0x5C, 0x1D, 0x2E, 0x80])),
            pages: (0 ..< pageCount).map { .init(number: UInt8($0), data: Data(repeating: 0, count: 4)) },
            ndefMessage: ndef?.data
        )
    }

    @Test
    func `English counts of one are singular`() {
        let text = DumpSummaryText.english
        #expect(text.pages(1) == "1 page")
        #expect(text.blocks(1) == "1 block")
        #expect(text.files(1) == "1 file")
        #expect(text.ndefBytes(1) == "1 NDEF byte")
        #expect(text.bytes(1) == "1 byte")
        #expect(text.ndefRecords(1) == "1 NDEF record")
    }

    @Test
    func `English counts other than one are plural`() {
        let text = DumpSummaryText.english
        #expect(text.pages(16) == "16 pages")
        #expect(text.pages(0) == "0 pages")
        #expect(text.blocks(2) == "2 blocks")
        #expect(text.files(3) == "3 files")
        #expect(text.ndefBytes(12) == "12 NDEF bytes")
        #expect(text.bytes(64) == "64 bytes")
        #expect(text.pair("16 pages", "64 bytes") == "16 pages, 64 bytes")
        #expect(text.ndefRecords(2) == "2 NDEF records")
    }

    @Test
    func `Simplified Chinese counts have one form`() {
        let text = DumpSummaryText.language("zh-Hans")
        #expect(text.pages(1) == "1 页")
        #expect(text.pages(16) == "16 页")
        #expect(text.bytes(64) == "64 字节")
        #expect(text.ndefRecords(1) == "1 条 NDEF 记录")
        #expect(text.capturedSummary("16 页", from: "卡片") == "已从 卡片 采集 16 页。")
        #expect(text.pair("16 页", "64 字节") == "16 页，64 字节")
    }

    @Test
    func `Summary of a one-record Ultralight dump uses singular and plural`() {
        let summary = ultralightDump(pageCount: 16).summary
        #expect(summary.technicalSummary == "16 pages, 64 bytes, 1 NDEF record")
        #expect(summary.userSummary == "Read a Type 2 style memory map with 16 pages.")
    }

    @Test
    func `Summary of a one-page dump is singular`() {
        let summary = ultralightDump(pageCount: 1, ndef: nil).summary
        #expect(summary.technicalSummary == "1 page, 4 bytes")
        #expect(summary.userSummary == "Read a Type 2 style memory map with 1 page.")
    }

    @Test
    func `Summary of a dump without memory says identification only`() {
        let dump = MemoryDump(cardInfo: CardInfo(type: .mifareUltralight, uid: Data([0x01])))
        #expect(dump.summary.technicalSummary == "identification only, 0 bytes")
    }

    @Test
    func `Technical summary lines are the size, then the NDEF records`() {
        let dump = ultralightDump(pageCount: 16)
        #expect(dump.technicalSummaryLines(text: .english, storageSummary: "16 pages") == ["16 pages, 64 bytes", "1 NDEF record"])
        let chinese = DumpSummaryText.language("zh-Hans")
        #expect(dump.technicalSummaryLines(text: chinese, storageSummary: chinese.pages(16)) == ["16 页，64 字节", "1 条 NDEF 记录"])
        #expect(dump.summary(text: chinese).technicalSummary == "16 页，64 字节，1 条 NDEF 记录")
        #expect(ultralightDump(pageCount: 1, ndef: nil).technicalSummaryLines(text: .english, storageSummary: "1 page") == ["1 page, 4 bytes"])
    }

    @Test
    func `Technical summary joins its parts without middle dots`() {
        let summary = ultralightDump(pageCount: 16).summary.technicalSummary
        #expect(!summary.contains("\u{00B7}"))
        #expect(!summary.contains("\u{2022}"))
    }

    @Test
    func `Smart Poster shows its title with the URI in parentheses`() {
        #expect(NDEFRecord.smartPoster(uri: "https://example.com", title: "Example").displayValue == "Example (https://example.com)")
        #expect(NDEFRecord.smartPoster(uri: "https://example.com").displayValue == "https://example.com")
    }

    @Test
    func `Localized summary keeps the capabilities of the English one`() {
        let dump = ultralightDump(pageCount: 16)
        #expect(dump.localizedSummary.capabilities == dump.summary.capabilities)
    }
}
