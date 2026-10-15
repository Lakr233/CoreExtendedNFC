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

    private let singaporeDateFormatter = DateFormatter().then {
        $0.dateStyle = .medium
        $0.timeStyle = .medium
        $0.timeZone = TimeZone(secondsFromGMT: 8 * 60 * 60)
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
        addSectionFooter(
            String(
                localized:
                    "Supports Japan IC (Suica, PASMO, ICOCA…), Hong Kong Octopus, Korea T-Money/Cashbee, China T-Union, and traditional Singapore EZ-Link/CEPAS. SimplyGo history is not supported."
            ))

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
            AppLogStore.shared.info("Starting transit card scan", source: "Transit")
            do {
                let (info, transport) = try await manager.scan(for: [.all])
                AppLogStore.shared.info("Detected tag; initial AID=\(info.initialSelectedAID ?? "none")", source: "Transit")
                // Transit detection must run before refinement changes the selected application.
                manager.setAlertMessage(String(localized: "Reading..."))
                let balance = try await CoreExtendedNFC.readTransitBalance(info: info, transport: transport)
                AppLogStore.shared.info(
                    "Read succeeded: balance=\(balance.balanceRaw) \(balance.currencyCode), transactions=\(balance.transactions.count)",
                    source: "Transit"
                )
                manager.setAlertMessage(String(localized: "Done"))
                manager.invalidate()

                displayResults(balance)
            } catch is CancellationError {
                manager.invalidate()
                AppLogStore.shared.info("Transit card scan cancelled", source: "Transit")
                return
            } catch {
                manager.invalidate()
                AppLogStore.shared.error("Transit card scan failed: \(error)", source: "Transit")
                if !presentNFCErrorAlertIfNeeded(for: error) {
                    presentErrorAlert(for: error)
                }
            }
        }
    }

    // MARK: - Display Results

    func displayResults(_ balance: TransitBalance) {
        dateFormatter.timeZone = balance.currencyCode == "SGD" ? TimeZone(secondsFromGMT: 8 * 60 * 60) : .current
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
            value: balance.formattedBalance,
            wrapValue: true
        )

        addInfoRow(
            icon: "info.circle",
            title: String(localized: "Raw"),
            value: balance.currencyCode == "SGD" ? String(localized: "\(String(balance.balanceRaw)) SGD cents") : "\(balance.balanceRaw) \(balance.currencyCode)",
            wrapValue: true
        )

        // Transaction History
        if !balance.transactions.isEmpty {
            addSectionHeader(String(localized: "Transaction History"))

            for (index, tx) in balance.transactions.enumerated() {
                let typeLabel =
                    switch tx.type {
                    case .trip: String(localized: "Trip")
                    case .topup: String(localized: "Top-up")
                    case .purchase: String(localized: "Purchase")
                    case .unknown: String(localized: "Unknown")
                    }

                var details = [typeLabel]
                if tx.type == .unknown, let rawType = tx.metadata["transactionType"] {
                    details.append(String(localized: "Type: 0x\(rawType)"))
                }
                if let date = tx.date {
                    if balance.currencyCode == "SGD" {
                        details.append(String(localized: "\(singaporeDateFormatter.string(from: date)) (Singapore time)"))
                    } else {
                        details.append(dateFormatter.string(from: date))
                    }
                }
                if let entry = tx.entryStation {
                    details.append(String(localized: "Entry: \(entry)"))
                }
                if let exit = tx.exitStation {
                    details.append(String(localized: "Exit: \(exit)"))
                }
                if let route = tx.metadata["busRoute"] {
                    details.append(String(localized: "Bus: \(route)"))
                }

                let value: String
                if let amount = tx.amount {
                    if balance.currencyCode == "SGD" {
                        let change = tx.metadata["balanceChange"].flatMap(Int.init)
                        let sign = change.map { $0 < 0 ? "−" : $0 > 0 ? "+" : "" } ?? ""
                        value = sign + String(format: "S$%.2f", Double(amount) / 100)
                    } else {
                        value = tx.balanceAfter.map { "\(amount) → \($0)" } ?? "\(amount)"
                    }
                } else {
                    value = tx.balanceAfter.map { "— → \($0)" } ?? "—"
                }
                addInfoRow(
                    icon: tx.type == .topup ? "plus.circle" : "arrow.right.circle",
                    title: "#\(index + 1)",
                    description: details.joined(separator: " · "),
                    value: value,
                    wrapValue: true
                )
            }

            addSectionFooter(String(localized: "\(balance.transactions.count) transaction(s)"))
        }
    }

    private func clearResults() {
        if let idx = stackView.arrangedSubviews.firstIndex(of: resultSentinel) {
            let toRemove = stackView.arrangedSubviews.suffix(from: idx + 1)
            for view in toRemove {
                view.removeFromSuperview()
            }
        }
    }
}
