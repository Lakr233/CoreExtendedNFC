import Foundation
import Testing

struct NFCConfigurationTests {
    @Test
    func `ISO7816 select identifiers include implemented transit AIDs`() throws {
        let identifiers = try #require(
            Bundle.main.object(
                forInfoDictionaryKey: "com.apple.developer.nfc.readersession.iso7816.select-identifiers"
            ) as? [String]
        )

        #expect(identifiers.contains("A000000632010105")) // China T-Union
        #expect(identifiers.contains("5041592E535A54")) // Legacy Shenzhen Tong
        #expect(identifiers.contains("A000000341000101")) // Singapore CEPAS discovery
        #expect(identifiers.contains("D4100000030001")) // KSX6924 / Snapper-compatible discovery
    }
}
