import ConfigurableKit
import CoreExtendedNFC
import SPIndicator
import SnapKit
import Then
import UIKit

class TransitBalanceViewController: StackScrollController {
    private let dateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .none
    }

    private var resultSentinel = UIView()

    override func viewDidLoad() {
        super.viewDidLoad()
        setupDismissKeyboardOnTap()
        view.backgroundColor = .systemBackground
        navigationItem.largeTitleDisplayMode = .never
        enableExtendedEdge()
    }

    override func setupContentViews() {
        super.setupContentViews()

        addSectionHeader(String(localized: "Transit Balance"))
        buildScanButton()
        addSectionFooter(String(localized: "Supports Japan IC (Suica, PASMO, ICOCA…), Korea T-Money/Cashbee, China T-Union."))

        stackView.addArrangedSubview(resultSentinel)
    }

    // MARK: - Scan Button

    private func buildScanButton() {
        let button = UIButton(type: .system).then {
            $0.setTitle(String(localized: "Scan Transit Card"), for: .normal)
            $0.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            $0.addTarget(self, action: #selector(scanTapped), for: .touchUpInside)
        }

        stackView.addArrangedSubviewWithMargin(button)
    }

    @objc private func scanTapped() {
        performScan()
    }

    // MARK: - NFC Scan

    private func performScan() {
        Task {
            let manager = NFCSessionManager()
            do {
                let (coarseInfo, transport) = try await manager.scan(for: [.all])
                let refinedInfo = try await CoreExtendedNFC.refineCardInfo(coarseInfo, transport: transport)

                manager.setAlertMessage(String(localized: "Reading..."))
                let balance = try await CoreExtendedNFC.readTransitBalance(
                    info: refinedInfo,
                    transport: transport
                )
                manager.setAlertMessage(String(localized: "Done"))
                manager.invalidate()

                displayResults(balance)
            } catch is CancellationError {
                return
            } catch {
                manager.invalidate()
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    // MARK: - Display Results

    private func displayResults(_ balance: TransitBalance) {
        clearResults()

        // Card Info
        addSectionHeader(String(localized: "Card Info"))

        addInfoRow(
            icon: "creditcard",
            title: String(localized: "Card"),
            value: balance.cardName
        )

        if !balance.serialNumber.isEmpty {
            addInfoRow(
                icon: "number",
                title: String(localized: "Serial Number"),
                value: balance.serialNumber
            )
        }

        if let validFrom = balance.validFrom {
            addInfoRow(
                icon: "calendar",
                title: String(localized: "Valid From"),
                value: dateFormatter.string(from: validFrom)
            )
        }

        if let validUntil = balance.validUntil {
            addInfoRow(
                icon: "calendar.badge.clock",
                title: String(localized: "Valid Until"),
                value: dateFormatter.string(from: validUntil)
            )
        }

        // Balance
        addSectionHeader(String(localized: "Balance"))

        addInfoRow(
            icon: "banknote",
            title: String(localized: "Balance"),
            value: balance.formattedBalance
        )

        addInfoRow(
            icon: "info.circle",
            title: String(localized: "Raw"),
            value: "\(balance.balanceRaw) \(balance.currencyCode)"
        )

        // Transaction History
        if !balance.transactions.isEmpty {
            addSectionHeader(String(localized: "Transaction History"))

            for (index, tx) in balance.transactions.enumerated() {
                let typeLabel = switch tx.type {
                case .trip: String(localized: "Trip")
                case .topup: String(localized: "Top-up")
                case .purchase: String(localized: "Purchase")
                case .unknown: String(localized: "Unknown")
                }

                let dateStr = tx.date.map { dateFormatter.string(from: $0) } ?? ""
                let description = dateStr.isEmpty ? typeLabel : "\(typeLabel) · \(dateStr)"

                addInfoRow(
                    icon: tx.type == .topup ? "plus.circle" : "arrow.right.circle",
                    title: "#\(index + 1)",
                    description: description,
                    value: "\(tx.amount) → \(tx.balanceAfter)"
                )
            }

            addSectionFooter(String(localized: "\(balance.transactions.count) transaction(s)"))
        }
    }

    private func clearResults() {
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            toRemove.forEach { $0.removeFromSuperview() }
        }
    }

    // MARK: - Error Handling

    private func presentErrorAlert(for error: Error) {
        let alert = UIAlertController(
            title: String(localized: "Error"),
            message: String(describing: error),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default))
        present(alert, animated: true)
    }
}
