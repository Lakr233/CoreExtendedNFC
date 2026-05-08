@testable import CoreExtendedNFC
import Testing

struct TransitBalanceTests {
    @Test
    func `Formats TWD balance`() {
        let balance = TransitBalance(
            serialNumber: "",
            balanceRaw: 245,
            currencyCode: "TWD",
            cardName: "EasyCard"
        )

        #expect(balance.formattedBalance == "NT$245")
    }
}
