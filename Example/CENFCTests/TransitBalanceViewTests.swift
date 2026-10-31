import CoreExtendedNFC
import Testing
import UIKit

@testable import CENFC

@MainActor
struct TransitBalanceViewTests {
    @Test(arguments: [UIContentSizeCategory.large, .accessibilityExtraExtraExtraLarge])
    func singaporeAmountsFitNarrowRows(contentSize: UIContentSizeCategory) throws {
        let controller = TransitBalanceViewController()
        let traits = UITraitCollection(preferredContentSizeCategory: contentSize)
        let scene = try #require(UIApplication.shared.connectedScenes.first as? UIWindowScene)
        let window = UIWindow(windowScene: scene)
        window.frame = CGRect(x: 0, y: 0, width: 320, height: 800)
        window.rootViewController = controller
        window.isHidden = false
        defer { window.isHidden = true }
        controller.traitOverrides.preferredContentSizeCategory = contentSize
        controller.displayResults(
            TransitBalance(
                serialNumber: "",
                balanceRaw: 244,
                currencyCode: "SGD",
                cardName: "EZ-Link",
                transactions: [
                    TransitTransaction(type: .trip, amount: 128, entryStation: "ABC", exitStation: "DEF", metadata: ["balanceChange": "-128"]),
                    TransitTransaction(type: .topup, amount: 500, metadata: ["balanceChange": "500"]),
                    TransitTransaction(type: .unknown, metadata: ["transactionType": "F0"]),
                ]
            )
        )
        controller.view.layoutIfNeeded()
        controller.view.layoutIfNeeded()
        #expect(controller.traitCollection.preferredContentSizeCategory == contentSize)
        #expect(controller.view.bounds.width == 320)

        let rows = infoRows(in: controller.view)
        let transactions = rows.filter { $0.titleLabel.text?.hasPrefix("#") == true }
        #expect(transactions.map { $0.valueLabel.attributedTitle(for: .normal)?.string } == ["−S$1.28", "+S$5.00", "—"])
        #expect(rows.contains { $0.valueLabel.attributedTitle(for: .normal)?.string == String(localized: "\(String(244)) SGD cents") })
        #expect(transactions.last?.descriptionLabel.text?.contains("0xF0") == true)

        for row in transactions {
            let label = try #require(row.valueLabel.titleLabel)
            let font = try #require(label.attributedText?.attribute(.font, at: 0, effectiveRange: nil) as? UIFont)
            #expect(font.pointSize == UIFont.preferredFont(forTextStyle: .subheadline, compatibleWith: traits).pointSize)
            #expect(row.bounds.width > 0)
            #expect(label.bounds.width > 0)
            let neededHeight = label.sizeThatFits(CGSize(width: label.bounds.width, height: .greatestFiniteMagnitude)).height
            #expect(label.bounds.height >= neededHeight - 1)
            #expect(label.frame.minY >= -1)
            #expect(label.frame.maxY <= row.valueLabel.bounds.height + 1)
            #expect(row.frame.maxX <= controller.view.bounds.width)
        }

        controller.displayResults(
            TransitBalance(
                serialNumber: "",
                balanceRaw: 1234,
                currencyCode: "JPY",
                cardName: "Suica",
                transactions: [TransitTransaction(type: .trip, balanceAfter: 1234)]
            )
        )
        let japanHistory = infoRows(in: controller.view).filter { $0.titleLabel.text?.hasPrefix("#") == true }
        #expect(japanHistory.map { $0.valueLabel.attributedTitle(for: .normal)?.string } == ["— → ¥1234"])
        controller.addInfoRow(icon: "info.circle", title: "Empty", value: "")
        controller.view.layoutIfNeeded()
        #expect(infoRows(in: controller.view).last?.valueLabel.attributedTitle(for: .normal)?.string == "")

        let longValue = String(repeating: "1234567890", count: 4)
        controller.addInfoRow(icon: "info.circle", title: "Amount", value: longValue, wrapValue: true)
        controller.addInfoRow(icon: "info.circle", title: "Amount", value: longValue)
        let comparisonRows = Array(infoRows(in: controller.view).suffix(2))
        let reconfigured = try #require(comparisonRows.first)
        let fresh = try #require(comparisonRows.last)
        controller.view.layoutIfNeeded()
        controller.view.layoutIfNeeded()
        #expect(reconfigured.bounds.height > fresh.bounds.height)

        reconfigured.configure(value: longValue)
        controller.view.layoutIfNeeded()
        controller.view.layoutIfNeeded()
        #expect(abs(reconfigured.bounds.height - fresh.bounds.height) < 1)
        #expect(abs(reconfigured.valueLabel.bounds.width - fresh.valueLabel.bounds.width) < 1)
        #expect(abs(reconfigured.verticalStack.bounds.width - fresh.verticalStack.bounds.width) < 1)
    }

    @Test
    func `History dates are shown in the card's time zone`() throws {
        let previousDefault = NSTimeZone.default
        NSTimeZone.default = try #require(TimeZone(identifier: "America/Los_Angeles"))
        defer { NSTimeZone.default = previousDefault }

        // Japan IC history dates are built at 00:00 Asia/Tokyo.
        var components = DateComponents()
        components.year = 2026
        components.month = 3
        components.day = 5
        components.timeZone = TimeZone(identifier: "Asia/Tokyo")
        let date = try #require(Calendar(identifier: .gregorian).date(from: components))

        let controller = TransitBalanceViewController()
        controller.loadViewIfNeeded()
        controller.displayResults(
            TransitBalance(
                serialNumber: "",
                balanceRaw: 1000,
                currencyCode: "JPY",
                cardName: "Suica",
                transactions: [TransitTransaction(type: .trip, balanceAfter: 1000, date: date)]
            )
        )

        let expected = DateFormatter()
        expected.dateStyle = .medium
        expected.timeStyle = .none
        expected.timeZone = TimeZone(identifier: "Asia/Tokyo")
        let losAngeles = DateFormatter()
        losAngeles.dateStyle = .medium
        losAngeles.timeStyle = .none
        losAngeles.timeZone = TimeZone(identifier: "America/Los_Angeles")

        let row = try #require(infoRows(in: controller.view).first { $0.titleLabel.text == "#1" })
        let description = try #require(row.descriptionLabel.text)
        #expect(description.contains(expected.string(from: date)))
        #expect(!description.contains(losAngeles.string(from: date)))
    }

    @Test
    func `Tap events are listed with their event, mode, station and distance`() throws {
        let controller = TransitBalanceViewController()
        controller.loadViewIfNeeded()
        controller.displayResults(
            TransitBalance(
                serialNumber: "",
                balanceRaw: 5000,
                currencyCode: "KRW",
                cardName: "T-Money",
                tapEvents: [TransitTransaction(type: .trip, exitStation: "00000290", mode: .rail, event: .tapOff, distanceMeters: 12900)]
            )
        )

        let row = try #require(infoRows(in: controller.view).first { $0.titleLabel.text == "#1" })
        #expect(row.valueLabel.attributedTitle(for: .normal)?.string == TransitBalanceViewController.tapEventLabel(.tapOff))
        let description = try #require(row.descriptionLabel.text)
        #expect(description.contains(TransitBalanceViewController.modeLabel(.rail)))
        #expect(description.contains("00000290"))
        #expect(description.contains(TransitBalanceViewController.formatDistance(meters: 12900)))
    }

    @Test
    func `Minor-unit transaction amounts are formatted in the card currency`() {
        // T-Union stores signed fen; a ¥2.50 fare used to show as "-250".
        #expect(TransitBalanceViewController.formatAmount(minorUnits: -250, currencyCode: "CNY") == "−¥2.50")
        #expect(TransitBalanceViewController.formatAmount(minorUnits: 1234, currencyCode: "CNY") == "¥12.34")
        #expect(TransitBalanceViewController.formatAmount(minorUnits: 1050, currencyCode: "HKD") == "HK$10.50")
        #expect(TransitBalanceViewController.formatAmount(minorUnits: 1250, currencyCode: "KRW") == "₩1250")
        #expect(TransitBalanceViewController.cardTimeZone(forCurrency: "KRW").identifier == "Asia/Seoul")
    }

    @Test
    func `Transaction amounts are unsigned magnitudes signed by transaction type`() {
        let format = TransitBalanceViewController.formatTransactionAmount
        // T-Union fare of ¥2.50 (amount is now a magnitude, not -250).
        #expect(format(TransitTransaction(type: .trip, amount: 250), "CNY") == "−¥2.50")
        #expect(format(TransitTransaction(type: .purchase, amount: 1200), "KRW") == "−₩1200")
        #expect(format(TransitTransaction(type: .topup, amount: 1000), "JPY") == "+¥1000")
        #expect(format(TransitTransaction(type: .unknown, amount: 5), "HKD") == "HK$0.05")
        // KS X 6924 "Snapper" cards report NZD in cents.
        #expect(format(TransitTransaction(type: .trip, amount: 345), "NZD") == "−NZ$3.45")
        #expect(TransitBalanceViewController.cardTimeZone(forCurrency: "NZD").identifier == "Pacific/Auckland")
        // CEPAS: the signed balance change decides, and is never applied twice.
        #expect(format(TransitTransaction(type: .unknown, amount: 128, metadata: ["balanceChange": "-128"]), "SGD") == "−S$1.28")
        #expect(format(TransitTransaction(type: .topup, amount: 500, metadata: ["balanceChange": "500"]), "SGD") == "+S$5.00")
        #expect(format(TransitTransaction(type: .trip), "SGD") == nil)
    }

    private func infoRows(in view: UIView) -> [ConfigurableInfoView] {
        if let row = view as? ConfigurableInfoView { return [row] }
        return view.subviews.flatMap { infoRows(in: $0) }
    }
}
