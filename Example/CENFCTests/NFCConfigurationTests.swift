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
        #expect(identifiers.contains("A000000404")) // CardBal transit / stored-value app
        #expect(identifiers.contains("5041592E535A54")) // Legacy Shenzhen Tong
        #expect(identifiers.contains("A000000341000101")) // Singapore CEPAS discovery
        #expect(identifiers.contains("D4100000030001")) // KSX6924 / Snapper-compatible discovery
        #expect(identifiers.contains("D4100000300001")) // MOIBA
        #expect(identifiers.contains("D4106509900020")) // K-Cash
    }

    @Test
    func `FeliCa system codes include CardBal transit codes`() throws {
        let systemCodes = try #require(
            Bundle.main.object(
                forInfoDictionaryKey: "com.apple.developer.nfc.readersession.felica.systemcodes"
            ) as? [String]
        )

        #expect(systemCodes.contains("0003")) // Japan IC
        #expect(systemCodes.contains("8008")) // Octopus
        #expect(systemCodes.contains("FE00")) // Rakuten Edy, WAON, nanaco (FeliCa common area)
        #expect(systemCodes.contains("80DE")) // IruCa
        #expect(systemCodes.contains("865E")) // SAPICA
        #expect(systemCodes.contains("8592")) // PASPY
        #expect(systemCodes.contains("8FC1")) // OKICA
        #expect(systemCodes.contains("927A")) // Hayakaken's additional system
    }
}
