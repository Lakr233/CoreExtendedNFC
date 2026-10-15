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
        #expect(japanHistory.map { $0.valueLabel.attributedTitle(for: .normal)?.string } == ["— → 1234"])
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

    private func infoRows(in view: UIView) -> [ConfigurableInfoView] {
        if let row = view as? ConfigurableInfoView { return [row] }
        return view.subviews.flatMap { infoRows(in: $0) }
    }
}
